package pl.legit.passwordwallet;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
class WalletItemsRepository {

    private final JdbcTemplate jdbcTemplate;

    private final static RowMapper<WalletItem> ROW_MAPPER = (row, num) -> new WalletItem(
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
