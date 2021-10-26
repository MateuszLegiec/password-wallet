package pl.legit.passwordwallet;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

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
        final var oldKey = generateKey(password);
        try {
            return decrypt(webAddressPassword, oldKey);
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
