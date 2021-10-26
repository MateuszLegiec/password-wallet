package pl.legit.passwordwallet;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class SHA512StrategyTest {

    private final String USERNAME = "username";
    private final String PASSWORD_HASH = "c62659937d57380280fd707b34f7c284647b085a42656ea916859ad566c172fadb940dec2beb34826998c61b1a26af0df4c7a6382826c075aa3eaa46d40af1e0";
    private final String PASSWORD = "password";
    private final byte[] SALT = new byte[]{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

    @Mock
    UsersRepository usersRepository;
    @Mock
    SaltGenerator saltGenerator;
    @InjectMocks
    SHA512Strategy sha512Strategy;

    @BeforeEach
    void setUp(){
        Mockito.when(saltGenerator.generateSalt()).thenReturn(new byte[]{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0});
        Mockito.when(usersRepository.findByUsername(USERNAME)).thenReturn(Optional.of(new User(USERNAME, PASSWORD_HASH, SALT, HashFunction.sha512)));
    }

    @Test
    void whenUserRegistersThenPasswordShouldBeEncoded(){
        final var registeredUser = sha512Strategy.create(USERNAME, PASSWORD);
        assertEquals(registeredUser.getPasswordHash(), PASSWORD_HASH);
    }

    @Test
    void whenUserLoginsWithValidPasswordThenStrategyShouldReturnTrue(){
        assertTrue(sha512Strategy.authenticate(USERNAME, PASSWORD));
    }

    @Test
    void whenUserChangingPasswordThenAllWalletItemPasswordShouldBeChanged(){

    }

}
