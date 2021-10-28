package pl.legit.passwordwallet;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

@Service
record ApplicationService(SecurityStrategy sha512Strategy, SecurityStrategy hmacStrategy, WalletItemsRepository walletItemsRepository, UsersRepository usersRepository) {

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

    public List<WalletItem> getWalletItems(String username) {
        return walletItemsRepository.findAllByUsername(username);
    }

    public void putWalletItem(String username, String webAddress, String webAddressUsername, String webAddressPassword, String userPassword) {
        walletItemsRepository.saveWallet(
                new WalletItem(username, webAddress, webAddressUsername, webAddressPassword, userPassword)
        );
    }

    public String decryptWalletItemPassword(String username, String webAddress, String userPassword) {
        return walletItemsRepository.findByUsernameAndWebService(username, webAddress)
                .map(it -> it.getDecryptedWebAddressPassword(userPassword))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    private SecurityStrategy securityStrategy(HashFunction hashFunction) {
        return switch (hashFunction) {
            case hmac -> hmacStrategy;
            case sha512 -> sha512Strategy;
        };
    }

}

sealed abstract class SecurityStrategy permits SHA512Strategy, HMACStrategy {

    protected final UsersRepository usersRepository;
    protected final WalletItemsRepository walletItemsRepository;

    protected SecurityStrategy(UsersRepository usersRepository, WalletItemsRepository walletItemsRepository) {
        this.usersRepository = usersRepository;
        this.walletItemsRepository = walletItemsRepository;
    }

    abstract User create(String username, String password);

    abstract boolean authenticate(String username, String password);

    void changePassword(String username, String oldPassword, String newPassword) {
        final var user = create(username, newPassword);
        usersRepository.saveUser(user);
        AtomicBoolean errorOccurred = new AtomicBoolean(false);
        final var walletItems = walletItemsRepository.findAllByUsername(username)
                .stream().peek(it -> {
                    try {
                        it.setWebAddressPassword(oldPassword, newPassword);
                    } catch (Exception e) {
                        errorOccurred.set(true);
                        e.printStackTrace();
                    }
                });
        if (errorOccurred.get()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT);
        } else {
            walletItems.forEach(walletItemsRepository::saveWallet);
        }
    }
}

@Component("sha512Strategy")
final class SHA512Strategy extends SecurityStrategy {

    private final SaltGenerator saltGenerator;

    SHA512Strategy(UsersRepository usersRepository, WalletItemsRepository walletItemsRepository, SaltGenerator saltGenerator) {
        super(usersRepository, walletItemsRepository);
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

    HMACStrategy(UsersRepository usersRepository, WalletItemsRepository walletItemsRepository, @Value("hmacKey") String hmacKey) {
        super(usersRepository, walletItemsRepository);
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
