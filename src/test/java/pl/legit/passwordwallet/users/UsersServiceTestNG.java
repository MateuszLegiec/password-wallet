package pl.legit.passwordwallet.users;

import org.springframework.web.server.ResponseStatusException;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import pl.legit.passwordwallet.HashFunction;
import pl.legit.passwordwallet.walletItems.WalletItemsService;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;

public class UsersServiceTestNG {

    private final static WalletItemsService walletItemsService = new WalletItemsService(null) {
        @Override
        public void updateWalletItems(String username, String oldPassword, String newPassword) {
        }
    };

    private final static SaltGenerator saltGenerator =  new SaltGenerator() {
        @Override
        byte[] generateSalt() {
            return new byte[]{};
        }
    };

    private UsersRepository usersRepository;
    private UsersService usersService;

    @BeforeMethod
    public void initEach() {
        usersRepository = new UsersRepository(null) {
            final Map<String, User> users = new HashMap<>(
                    Map.of(
                            "username", new User("username", "hash", new byte[]{}, HashFunction.sha512),
                            "sha512_username", new User("sha512_username", "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86", new byte[]{}, HashFunction.sha512),
                            "hmac_username", new User("hmac_username", "RZJ3foZ/de2piTDs7g69Ayjzg/AbGxbRGlWN0hlHDjI5tBdPOR5WXCgLALhcMKJ5Lo+HTzp8gCR0SfGpv0VQ6Q==", null, HashFunction.hmac)
                    )
            );

            @Override
            Optional<User> findByUsername(String username) {
                return Optional.ofNullable(users.get(username));
            }

            @Override
            void saveUser(User user) {
                users.put(user.getUsername(), user);
            }
        };
        usersService = new UsersService(
                new SHA512Strategy(usersRepository, walletItemsService, saltGenerator),
                new HMACStrategy(usersRepository, walletItemsService, "hmac_key"),
                usersRepository
        );
    }

    @Test
    void testAuthenticationWhenUserNotExists() {
        assertThrows(ResponseStatusException.class, () -> usersService.authenticate("username_that_do_not_exists", "password"));
    }

    @Test
    void testRegisteringWhenUserWithUsernameAlreadyExists() {
        assertThrows(ResponseStatusException.class, () -> usersService.register("username", "password", HashFunction.sha512));
    }

    @Test(dataProvider = "usernameProvider")
    void testAuthenticationWithValidCredentials(String username) {
        assertDoesNotThrow(() -> usersService.authenticate(username, "password"));
    }

    @Test(dataProvider = "enabledUsernameProvider")
    void testRegistering(String username) {
        usersService.register(username, "password", HashFunction.hmac);

        assertTrue(usersRepository.findByUsername(username).isPresent());
        assertDoesNotThrow(() -> usersService.authenticate(username, "password"));
    }

    @Test(dataProvider = "usernameProvider")
    void testAuthenticationWithInvalidCredentials(String username) {
        assertThrows(ResponseStatusException.class, () -> usersService.authenticate(username, "invalid_password"));
    }

    @Test(dataProvider = "usernameProvider")
    void testPasswordChange(String username) {
        usersService.changePassword(username, "password", "new_password");
        assertDoesNotThrow(() -> usersService.authenticate(username, "new_password"));
    }

    public static void assertDoesNotThrow(Runnable action){
        try{
            action.run();
        }
        catch(Exception ex){
            Assert.fail(ex.getMessage());
        }
    }

    @DataProvider(name = "usernameProvider")
    public static Object[][] usernameProvider(){
        return new Object[][]{{"sha512_username"}, {"hmac_username"}};
    }

    @DataProvider(name = "enabledUsernameProvider")
    public static Object[][] enabledUsernameProvider(){
        return new Object[][]{{"sha512_username_2"}, {"hmac_username_2"}};
    }


}
