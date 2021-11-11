package pl.legit.passwordwallet.walletItems;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pl.legit.passwordwallet.WalletItemQuery;

import java.util.*;
import java.util.stream.Collectors;

class WalletItemsServiceTest {

    private WalletItemsRepository walletItemsRepository;
    private WalletItemsService walletItemsService;

    @BeforeEach
    public void initEach() {
        this.walletItemsRepository = new WalletItemsRepository(null) {
            final Set<WalletItem> items =
                    new HashSet<>(
                            Set.of(
                                    new WalletItem(
                                            "username",
                                            "facebook",
                                            "facebook_user",
                                            "5HcPhUVH+OZJ5QinjN3tYWmVHBobxSk/HuoCQTzkNyk="
                                    ),
                                    new WalletItem(
                                            "username",
                                            "twitter",
                                            "twitter_user",
                                            "Slc5gXAL+S1mRhfp/l/ry98jg8TkCL+4n/erTDGanbE="
                                    ),
                                    new WalletItem(
                                            "username",
                                            "instagram",
                                            "instagram_user",
                                            "5J3hG7il4P/vWZ4siyZ9KTYp5jVfe523+ZBA8KjAh9s="
                                    )
                            )
                    );

            @Override
            List<WalletItem> findAllByUsername(String username) {
                return items.stream().filter(it -> it.getUsername().equals(username)).collect(Collectors.toList());
            }

            @Override
            public List<WalletItemQuery> findAllQueriesByUsername(String username) {
                return items.stream()
                        .filter(it -> it.getUsername().equals(username))
                        .map(it -> new WalletItemQuery(it.getUsername(), it.getWebAddress(), it.getWebAddressUsername(), it.getWebAddressPassword()))
                        .collect(Collectors.toList());
            }

            @Override
            Optional<WalletItem> findByUsernameAndWebService(String username, String webService) {
                return items.stream()
                        .filter(it -> it.getUsername().equals(username) && it.getWebAddress().equals(webService))
                        .findFirst();
            }

            @Override
            void saveWallet(WalletItem wallet) {
                findByUsernameAndWebService(wallet.getUsername(), wallet.getWebAddress()).ifPresent(items::remove);
                items.add(wallet);
            }
        };

        this.walletItemsService = new WalletItemsService(this.walletItemsRepository);

    }

    @Test
    void testUpdatingItem() {
        //when
        walletItemsService.putWalletItem(
                "username",
                "facebook",
                "facebook_username",
                "updated_facebook_password",
                "user_password"
        );

        //then
        final Optional<WalletItem> item = walletItemsRepository.findByUsernameAndWebService("username", "facebook");
        Assertions.assertTrue(item.isPresent());
        Assertions.assertEquals("updated_facebook_password", item.get().getDecryptedWebAddressPassword("user_password"));
    }

    @Test
    void testCreatingItem() {
        //when
        walletItemsService.putWalletItem(
                "username",
                "google",
                "google_username",
                "google_password",
                "user_password"
        );

        //then
        Assertions.assertTrue(walletItemsRepository.findByUsernameAndWebService("username", "google").isPresent());
    }

    @Test
    void testUpdatingMultipleItems() {
        //when
        walletItemsService.updateWalletItems("username", "user_password", "updated_password");
        //then
        Map.of(
                "facebook", "facebook_password",
                "twitter", "twitter_password",
                "instagram", "instagram_password"
        ).forEach(
                (address, password) -> {
                    final Optional<WalletItem> item = walletItemsRepository.findByUsernameAndWebService("username", address);
                    Assertions.assertTrue(item.isPresent());
                    Assertions.assertEquals(password, item.get().getDecryptedWebAddressPassword("updated_password"));
                }
        );

    }

    @Test
    void testDecryptingPassword() {
        //then
        Assertions.assertEquals(
                "facebook_password",
                walletItemsService.decryptWalletItemPassword("username", "facebook", "user_password")
        );
    }

}
