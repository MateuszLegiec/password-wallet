package pl.legit.passwordwallet.walletItems;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Repository;
import org.springframework.web.server.ResponseStatusException;
import pl.legit.passwordwallet.WalletItemQuery;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

@Component
public class WalletItemsService {

    private final WalletItemsRepository walletItemsRepository;

    public WalletItemsService(WalletItemsRepository walletItemsRepository) {
        this.walletItemsRepository = walletItemsRepository;
    }

    public List<WalletItemQuery> getWalletItems(String username) {
        return walletItemsRepository.findAllQueriesByUsername(username);
    }

    public void putWalletItem(String username, String webAddress, String webAddressUsername, String webAddressPassword, String userPassword) {
        walletItemsRepository.saveWallet(
                new WalletItem(username, webAddress, webAddressUsername, webAddressPassword, userPassword)
        );
    }

    public void putWalletItem(String username, String webAddress, String webAddressUsername, String webAddressPassword) {
        walletItemsRepository.saveWallet(
                new WalletItem(username, webAddress, webAddressUsername, webAddressPassword)
        );
    }

    public String decryptWalletItemPassword(String username, String webAddress, String userPassword) {
        return walletItemsRepository.findByUsernameAndWebService(username, webAddress)
                .map(it -> it.getDecryptedWebAddressPassword(userPassword))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    public void updateWalletItems(String username, String oldPassword, String newPassword) {
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
            walletItems.forEach(it -> putWalletItem(it.getUsername(), it.getWebAddress(), it.getWebAddressUsername(), it.getWebAddressPassword()));
        }
    }
}

@Repository
class WalletItemsRepository {

    private final JdbcTemplate jdbcTemplate;

    private final static RowMapper<WalletItem> ROW_MAPPER = (row, num) -> new WalletItem(
            row.getString("USERNAME"),
            row.getString("WEB_ADDRESS"),
            row.getString("WEB_ADDRESS_USERNAME"),
            row.getString("WEB_ADDRESS_PASSWORD")
    );
    private final static RowMapper<WalletItemQuery> QUERY_ROW_MAPPER = (row, num) -> new WalletItemQuery(
            row.getString("USERNAME"),
            row.getString("WEB_ADDRESS"),
            row.getString("WEB_ADDRESS_USERNAME"),
            row.getString("WEB_ADDRESS_PASSWORD")
    );

    public WalletItemsRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    List<WalletItem> findAllByUsername(String username) {
        return jdbcTemplate.query(
                "SELECT USERNAME, WEB_ADDRESS, WEB_ADDRESS_USERNAME, WEB_ADDRESS_PASSWORD FROM WALLET_ITEMS WHERE USERNAME = ?",
                ROW_MAPPER,
                username
        );
    }

    public List<WalletItemQuery> findAllQueriesByUsername(String username) {
        return jdbcTemplate.query(
                "SELECT USERNAME, WEB_ADDRESS, WEB_ADDRESS_USERNAME, WEB_ADDRESS_PASSWORD FROM WALLET_ITEMS WHERE USERNAME = ?",
                QUERY_ROW_MAPPER,
                username
        );
    }

    Optional<WalletItem> findByUsernameAndWebService(String username, String webService) {
        try {
            return Optional.ofNullable(
                    jdbcTemplate.queryForObject(
                            "SELECT USERNAME, WEB_ADDRESS, WEB_ADDRESS_USERNAME, WEB_ADDRESS_PASSWORD FROM WALLET_ITEMS WHERE USERNAME = ? AND WEB_ADDRESS = ?",
                            ROW_MAPPER,
                            username,
                            webService
                    )
            );
        } catch (EmptyResultDataAccessException e){
            return Optional.empty();
        }
    }

    void saveWallet(WalletItem wallet) {
        findByUsernameAndWebService(wallet.getUsername(), wallet.getWebAddress()).ifPresentOrElse(
                it -> jdbcTemplate.update(
                        "UPDATE WALLET_ITEMS SET WEB_ADDRESS_USERNAME = ?, WEB_ADDRESS_PASSWORD = ? WHERE USERNAME = ? AND WEB_ADDRESS = ?",
                        wallet.getWebAddressUsername(),
                        wallet.getWebAddressPassword(),
                        wallet.getUsername(),
                        wallet.getWebAddress()
                ),
                () -> jdbcTemplate.update(
                        "INSERT INTO WALLET_ITEMS (USERNAME, WEB_ADDRESS, WEB_ADDRESS_USERNAME, WEB_ADDRESS_PASSWORD) VALUES (?, ?, ?, ?)",
                        wallet.getUsername(),
                        wallet.getWebAddress(),
                        wallet.getWebAddressUsername(),
                        wallet.getWebAddressPassword()
                )
        );
    }
}

final class WalletItem {

    private static final String AES = "AES";

    private final String username;
    private final String webAddress;
    private final String webAddressUsername;
    private String webAddressPassword;

    WalletItem(String username, String webAddress, String webAddressUsername, String webAddressPassword) {
        this.username = username;
        this.webAddress = webAddress;
        this.webAddressUsername = webAddressUsername;
        this.webAddressPassword = webAddressPassword;
    }

    WalletItem(String username, String webAddress, String webAddressUsername, String webAddressPassword, String userPassword) {
        this.username = username;
        this.webAddress = webAddress;
        this.webAddressUsername = webAddressUsername;
        try {
            this.webAddressPassword = encrypt(webAddressPassword, generateKey(userPassword));
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, e.getMessage());
        }
    }

    public void setWebAddressPassword(String userOldPassword, String userNewPassword) {
        final var newKey = generateKey(userNewPassword);
        try {
            this.webAddressPassword = encrypt(getDecryptedWebAddressPassword(userOldPassword), newKey);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, e.getMessage());
        }
    }

    public String getDecryptedWebAddressPassword(String password) {
        final var key = generateKey(password);
        try {
            return decrypt(webAddressPassword, key);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY);
        }
    }

    public String getUsername() {
        return username;
    }

    public String getWebAddress() {
        return webAddress;
    }

    public String getWebAddressUsername() {
        return webAddressUsername;
    }

    public String getWebAddressPassword() {
        return webAddressPassword;
    }

    private static String encrypt(String data, Key key) throws Exception {
        Cipher c = Cipher.getInstance(AES);
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encVal = c.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encVal);
    }

    private static String decrypt(String encryptedData, Key key) {
        try {
            Cipher c = Cipher.getInstance(AES);
            c.init(Cipher.DECRYPT_MODE, key);
            byte[] decodedValue = Base64.getDecoder().decode(encryptedData);
            byte[] decValue = c.doFinal(decodedValue);
            return new String(decValue);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            e.printStackTrace();
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY);
        }
    }

    private static Key generateKey(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] messageDigest = md.digest(password.getBytes());
            return new SecretKeySpec(messageDigest, AES);

        } catch (NoSuchAlgorithmException e) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY);
        }
    }
}
