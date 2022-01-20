package pl.legit.passwordwallet.users;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import pl.legit.passwordwallet.HashFunction;
import pl.legit.passwordwallet.walletItems.WalletItemsService;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;

@Service
public class UsersService {

    private final SecurityStrategy sha512Strategy;
    private final SecurityStrategy hmacStrategy;
    private final UsersRepository usersRepository;

    public UsersService(SecurityStrategy sha512Strategy, SecurityStrategy hmacStrategy, UsersRepository usersRepository) {
        this.sha512Strategy = sha512Strategy;
        this.hmacStrategy = hmacStrategy;
        this.usersRepository = usersRepository;
    }

    public void authenticate(String username, String password) {
        usersRepository.findByUsername(username)
                .ifPresentOrElse(
                        it -> {
                            if (!securityStrategy(it.getHash()).authenticate(username, password)) {
                                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
                            }
                        },
                        () -> {
                            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
                        }
                );
    }

    public void register(String username, String password, HashFunction hashFunction) {
        usersRepository.findByUsername(username).ifPresentOrElse(
                it -> {
                    throw new ResponseStatusException(HttpStatus.CONFLICT);
                },
                () -> usersRepository.saveUser(securityStrategy(hashFunction).create(username, password))
        );
    }

    public void changePassword(String username, String oldPassword, String newPassword) {
        usersRepository.findByUsername(username).ifPresentOrElse(
                it -> securityStrategy(it.getHash()).changePassword(it.getUsername(), oldPassword, newPassword),
                () -> {
                    throw new ResponseStatusException(HttpStatus.NOT_FOUND);
                }
        );
    }

    private SecurityStrategy securityStrategy(HashFunction hashFunction) {
        return switch (hashFunction) {
            case hmac -> hmacStrategy;
            case sha512 -> sha512Strategy;
        };
    }

    public boolean existsByUsername(String username) {
        return usersRepository.findByUsername(username).isPresent();
    }
}

sealed abstract class SecurityStrategy permits SHA512Strategy, HMACStrategy {

    protected final UsersRepository usersRepository;
    protected final WalletItemsService walletItemsService;

    protected SecurityStrategy(UsersRepository usersRepository, WalletItemsService walletItemsService) {
        this.usersRepository = usersRepository;
        this.walletItemsService = walletItemsService;
    }

    abstract User create(String username, String password);

    abstract boolean authenticate(String username, String password);

    void changePassword(String username, String oldPassword, String newPassword) {
        final var user = create(username, newPassword);
        usersRepository.saveUser(user);
        walletItemsService.updateWalletItems(username, oldPassword, newPassword);
    }
}

@Component("sha512Strategy")
final class SHA512Strategy extends SecurityStrategy {

    private final SaltGenerator saltGenerator;

    SHA512Strategy(UsersRepository usersRepository, WalletItemsService walletItemsService, SaltGenerator saltGenerator) {
        super(usersRepository, walletItemsService);
        this.saltGenerator = saltGenerator;
    }

    @Override
    public User create(String username, String password) {
        final var salt = saltGenerator.generateSalt();
        final var passwordHash = generatePassword(password, salt);
        return new User(
                username,
                passwordHash,
                salt,
                HashFunction.sha512
        );
    }

    @Override
    public boolean authenticate(String username, String password) {
        return usersRepository.findByUsername(username)
                .map(u -> generatePassword(password, u.getSalt()).equals(u.getPasswordHash()))
                .orElse(Boolean.FALSE);
    }

    private static String generatePassword(String password, byte[] salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            md.update(salt);
            byte[] messageDigest = md.digest(password.getBytes());
            BigInteger no = new BigInteger(1, messageDigest);
            String hashtext = no.toString(16);
            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }
            return hashtext;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

}

@Component
class SaltGenerator {
    byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }
}

@Component("hmacStrategy")
final class HMACStrategy extends SecurityStrategy {

    private final static String HMAC_SHA512 = "HmacSHA512";
    private final String hmacKey;

    HMACStrategy(UsersRepository usersRepository, WalletItemsService walletItemsService, @Value("hmacKey") String hmacKey) {
        super(usersRepository, walletItemsService);
        this.hmacKey = hmacKey;
    }

    @Override
    public User create(String username, String password) {
        return new User(
                username,
                generatePassword(password, hmacKey),
                null,
                HashFunction.hmac
        );
    }

    @Override
    public boolean authenticate(String username, String password) {
        return usersRepository.findByUsername(username)
                .map(u -> generatePassword(password, hmacKey).equals(u.getPasswordHash()))
                .orElse(Boolean.FALSE);
    }

    public static String generatePassword(String text, String key) {
        Mac sha512Hmac;
        String result = "";
        try {
            final byte[] byteKey = key.getBytes(StandardCharsets.UTF_8);
            sha512Hmac = Mac.getInstance(HMAC_SHA512);
            SecretKeySpec keySpec = new SecretKeySpec(byteKey, HMAC_SHA512);
            sha512Hmac.init(keySpec);
            byte[] macData = sha512Hmac.doFinal(text.getBytes(StandardCharsets.UTF_8));
            result = Base64.getEncoder().encodeToString(macData);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return result;
    }

}

@Repository
class UsersRepository {

    private final static RowMapper<User> ROW_MAPPER = (row, num) -> new User(
            row.getString("USERNAME"),
            row.getString("PASSWORD_HASH"),
            row.getBytes("SALT"),
            HashFunction.valueOf(row.getString("HASH_FUNCTION"))
    );

    private final JdbcTemplate jdbcTemplate;

    UsersRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    Optional<User> findByUsername(String username) {
        try {
            return Optional.ofNullable(jdbcTemplate.queryForObject(
                            "SELECT USERNAME, PASSWORD_HASH, SALT, HASH_FUNCTION FROM USERS WHERE USERNAME = ?",
                            ROW_MAPPER,
                            username
                    )
            );
        } catch (EmptyResultDataAccessException e){
            return Optional.empty();
        }
    }

    void saveUser(User user) {
        findByUsername(user.getUsername()).ifPresentOrElse(
                it -> jdbcTemplate.update(
                        "UPDATE USERS SET PASSWORD_HASH = ?, SALT = ?, HASH_FUNCTION =? WHERE USERNAME = ?",
                        user.getPasswordHash(),
                        user.getSalt(),
                        user.getHash().name(),
                        user.getUsername()
                ),
                () -> jdbcTemplate.update(
                        "INSERT INTO USERS (USERNAME, PASSWORD_HASH, SALT, HASH_FUNCTION) VALUES (?, ?, ?, ?)",
                        user.getUsername(),
                        user.getPasswordHash(),
                        user.getSalt(),
                        user.getHash().name()
                )
        );
    }

}

record User(String username, String passwordHash, byte[] salt, HashFunction hash) {
    public String getUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public byte[] getSalt() {
        return salt;
    }

    public HashFunction getHash() {
        return hash;
    }
}
