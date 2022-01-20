package pl.legit.passwordwallet.watchers;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;
import pl.legit.passwordwallet.users.UsersService;

import java.util.List;

@Service
public class WatchersService {

    private final JdbcTemplate jdbcTemplate;
    private final UsersService usersService;

    private static RowMapper<String> ROW_MAPPER = (row, num) -> row.getString(1);

    public WatchersService(JdbcTemplate jdbcTemplate, UsersService usersService) {
        this.jdbcTemplate = jdbcTemplate;
        this.usersService = usersService;
    }

    public List<String> findAllSubjects(String watcher){
        return jdbcTemplate.query(
                "SELECT SUBJECT FROM SUBJECT_TO_OBSERVER WHERE OBSERVER = ?",
                ROW_MAPPER,
                watcher
        );
    }

    public List<String> findAllObservers(String watching){
        return jdbcTemplate.query(
                "SELECT OBSERVER FROM SUBJECT_TO_OBSERVER WHERE SUBJECT = ?",
                ROW_MAPPER,
                watching
        );
    }

    public void create(String subject, String observer){
        if (usersService.existsByUsername(subject) && !subject.equals(observer)){
            jdbcTemplate.update(
                    "INSERT INTO SUBJECT_TO_OBSERVER (SUBJECT, OBSERVER) VALUES (?, ?)",
                    subject,
                    observer
            );
        }
    }

}
