package pl.legit.passwordwallet;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.util.Optional;

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
