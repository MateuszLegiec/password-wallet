package pl.legit.passwordwallet;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
public class ApplicationController {

    private final ApplicationService applicationService;

    ApplicationController(ApplicationService applicationService) {
        this.applicationService = applicationService;
    }

    @GetMapping("/login")
    public ResponseEntity<Void> greeting() {
        return ResponseEntity.ok().build();
    }

    @PostMapping("/register")
    public void register(@RequestBody RegistrationCommand registrationCommand) {
        applicationService.register(registrationCommand.getUsername(), registrationCommand.getPassword(), registrationCommand.getHashFunction());
    }

    @PostMapping("/{username}/change-password")
    public void changePassword(@PathVariable String username, @RequestBody ChangePasswordCommand changePasswordCommand) {
        applicationService.changePassword(username, changePasswordCommand.getOldPassword(), changePasswordCommand.getNewPassword());
    }

    @GetMapping("/{username}/wallet-items")
    public List<WalletItem> getWalletPasswords(@PathVariable String username) {
        return applicationService.getWalletItems(username);
    }

    @GetMapping("/{username}/wallet-items/{webAddress}/password")
    public String decryptWalletPassword(@PathVariable String username, @PathVariable String webAddress, @RequestHeader("Authorization") String authorizationToken) {
        return applicationService.decryptWalletItemPassword(username, webAddress, SecurityUtils.decodeToken(authorizationToken).getPassword());
    }

    @PutMapping("/{username}/wallet-items/{webAddress}")
    public void putWalletItem(@PathVariable String username, @PathVariable String webAddress, @RequestBody PutWalletItemCommand credentials, @RequestHeader("Authorization") String authorizationToken) {
        applicationService.putWalletItem(username, webAddress, credentials.getWebAddressUsername(), credentials.getWebAddressPassword(), SecurityUtils.decodeToken(authorizationToken).getPassword());
    }

}

class RegistrationCommand extends CredentialsDTO {
    private HashFunction hashFunction;

    public HashFunction getHashFunction() {
        return hashFunction;
    }

    public void setHashFunction(HashFunction hashFunction) {
        this.hashFunction = hashFunction;
    }
}

class ChangePasswordCommand {
    private String oldPassword;
    private String newPassword;

    public String getNewPassword() {
        return newPassword;
    }
    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }
    public String getOldPassword() {
        return oldPassword;
    }
    public void setOldPassword(String oldPassword) {
        this.oldPassword = oldPassword;
    }
}

class CredentialsDTO {
    private String username;
    private String password;

    public CredentialsDTO(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public CredentialsDTO() {
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}

class PutWalletItemCommand {
    private String webAddressUsername;
    private String webAddressPassword;

    public String getWebAddressUsername() {
        return webAddressUsername;
    }

    public void setWebAddressUsername(String webAddressUsername) {
        this.webAddressUsername = webAddressUsername;
    }

    public String getWebAddressPassword() {
        return webAddressPassword;
    }

    public void setWebAddressPassword(String webAddressPassword) {
        this.webAddressPassword = webAddressPassword;
    }
}
