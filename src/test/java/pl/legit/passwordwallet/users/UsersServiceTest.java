package pl.legit.passwordwallet.users;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.web.server.ResponseStatusException;
import pl.legit.passwordwallet.HashFunction;
import pl.legit.passwordwallet.walletItems.WalletItemsService;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

class UsersServiceTest {

    private final static WalletItemsService walletItemsService = new WalletItemsService(null) {
        @Override
        public void updateWalletItems(String username, String oldPassword, String newPassword) {
        }
    };

    private final static SaltGenerator saltGenerator = new SaltGenerator() {
        @Override
        byte[] generateSalt() {
            return new byte[]{};
        }
    };

    private UsersRepository usersRepository;
    private UsersService usersService;

    @BeforeEach
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
        Assertions.assertThrows(ResponseStatusException.class, () -> usersService.authenticate("username_that_do_not_exists", "password"));
    }

    @Test
    void testRegisteringWhenUserWithUsernameAlreadyExists() {
        Assertions.assertThrows(ResponseStatusException.class, () -> usersService.register("username", "password", HashFunction.sha512));
    }

    @ParameterizedTest
    @ValueSource(strings = {"sha512_username", "hmac_username"})
    void testAuthenticationWithValidCredentials(String username) {
        usersService.authenticate(username, "password");
    }

    @ParameterizedTest
    @ValueSource(strings = {"sha512_username_2", "hmac_username_2"})
    void testRegistering(String username) {
        usersService.register(username, "password", HashFunction.hmac);

        Assertions.assertTrue(usersRepository.findByUsername(username).isPresent());
        Assertions.assertDoesNotThrow(() -> usersService.authenticate(username, "password"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"sha512_username", "hmac_username"})
    void testAuthenticationWithInvalidCredentials(String username) {
        Assertions.assertThrows(ResponseStatusException.class, () -> usersService.authenticate(username, "invalid_password"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"sha512_username", "hmac_username"})
    void testPasswordChange(String username) {
        usersService.changePassword(username, "password", "new_password");

        Assertions.assertDoesNotThrow(() -> usersService.authenticate(username, "new_password"));
    }

}
