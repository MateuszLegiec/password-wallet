package pl.legit.passwordwallet.loginAudit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class LoginAuditFacade {

    private final static Logger log = LoggerFactory.getLogger(LoginAuditFacade.class);

    private final LoginAuditRepository loginAuditRepository;
    private final BlockedIpRepository blockedIpRepository;
    private final int firstDelay;
    private final int secondDelay;
    private final int thirdDelay;

    public LoginAuditFacade(LoginAuditRepository loginAuditRepository,
                            BlockedIpRepository blockedIpRepository,
                            @Value("${auth.failure.firstDelay}") String firstDelay,
                            @Value("${auth.failure.secondDelay}") String secondDelay,
                            @Value("${auth.failure.thirdDelay}") String thirdDelay) {
        this.loginAuditRepository = loginAuditRepository;
        this.blockedIpRepository = blockedIpRepository;
        this.firstDelay = Integer.parseInt(firstDelay);
        this.secondDelay = Integer.parseInt(secondDelay);
        this.thirdDelay = Integer.parseInt(thirdDelay);
    }

    public enum OperationResult {
        success, failure
    }

    public void create(String username, String remoteAddress, OperationResult failure) {
        loginAuditRepository.save(username, remoteAddress, failure, LocalDateTime.now());
    }

    public boolean isUserBlocked(String username) {
        final List<LoginAudit> loginAudits = loginAuditRepository.findFirst4ByUsername(username);
        final List<Boolean> isFailureList = loginAudits.stream()
                .map(LoginAudit::operationResult)
                .map(it -> it.equals(OperationResult.failure))
                .collect(Collectors.toList());

        final boolean isIpBlockedForThirdDelay = isFailureList.size() >= 4 && isFailureList.get(0) && isFailureList.get(1) && isFailureList.get(2) && isFailureList.get(3);
        final boolean isIpBlockedForSecondDelay = isFailureList.size() >= 3 && isFailureList.get(0) && isFailureList.get(1) && isFailureList.get(2);
        final boolean isIpBlockedForFirstDelay = isFailureList.size() >= 2 && isFailureList.get(0) && isFailureList.get(1);

        if (isIpBlockedForThirdDelay){
            log.info("Checking if user with 3rd delay is blocked");
            return secondsFrom(loginAudits.get(0).creationDate()) < thirdDelay;
        } else if (isIpBlockedForSecondDelay) {
            log.info("Checking if user with 2nd delay is blocked");
            return secondsFrom(loginAudits.get(0).creationDate()) < secondDelay;
        } else if (isIpBlockedForFirstDelay) {
            log.info("Checking if user with 1st delay is blocked");
            return secondsFrom(loginAudits.get(0).creationDate()) < firstDelay;
        } else {
            return false;
        }
    }

    public boolean isIpBlocked(String remoteAddress) {
        final boolean isIpPermanentlyBlocked = blockedIpRepository.findById(remoteAddress).isPresent();

        if (isIpPermanentlyBlocked)
            return true;

        final List<LoginAudit> loginAudits = loginAuditRepository.findFirst4ByIpAddress(remoteAddress);
        final List<Boolean> isFailureList = loginAudits.stream()
                .map(LoginAudit::operationResult)
                .map(it -> it.equals(OperationResult.failure))
                .collect(Collectors.toList());

        final boolean isIpBlockedForThirdDelay = isFailureList.size() >= 4 && isFailureList.get(0) && isFailureList.get(1) && isFailureList.get(2) && isFailureList.get(3);
        final boolean isIpBlockedForSecondDelay = isFailureList.size() >= 3 && isFailureList.get(0) && isFailureList.get(1) && isFailureList.get(2);
        final boolean isIpBlockedForFirstDelay = isFailureList.size() >= 2 && isFailureList.get(0) && isFailureList.get(1);

        if (isIpBlockedForThirdDelay){
            log.info("Blocking ip: " + remoteAddress);
            blockedIpRepository.save(remoteAddress);
            return true;
        } else if (isIpBlockedForSecondDelay) {
            log.info("Checking if ip with 2nd delay is blocked");
            return secondsFrom(loginAudits.get(0).creationDate()) < secondDelay;
        } else if (isIpBlockedForFirstDelay) {
            log.info("Checking if ip with 1st delay is blocked");
            return secondsFrom(loginAudits.get(0).creationDate()) < firstDelay;
        } else {
            return false;
        }
    }

    private long secondsFrom(LocalDateTime from){
        return ChronoUnit.MILLIS.between(from, LocalDateTime.now());
    }

    public List<LoginAudit> findAllByUsername(String username) {
        return loginAuditRepository.findAllByUsername(username);
    }

    public List<String> findAllBlockedIps() {
        return blockedIpRepository.findAll();
    }

    public void deleteBlockedIpById(String id) {
        blockedIpRepository.deleteById(id);
    }

}

@Repository
class BlockedIpRepository {

    private final static RowMapper<String> ROW_MAPPER = (row, num) -> row.getString(1);

    private final JdbcTemplate jdbcTemplate;

    BlockedIpRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public List<String> findAll() {
        return jdbcTemplate.query(
                "SELECT IP_ADDRESS FROM BLOCKED_IPS",
                ROW_MAPPER
        );
    }

    public Optional<String> findById(String ip) {
        try {
            return Optional.ofNullable(
                    jdbcTemplate.queryForObject(
                            "SELECT IP_ADDRESS FROM BLOCKED_IPS WHERE IP_ADDRESS = ?",
                            ROW_MAPPER,
                            ip
                    )
            );
        } catch (EmptyResultDataAccessException e){
            return Optional.empty();
        }
    }

    public void deleteById(String ip) {
        jdbcTemplate.update("DELETE FROM BLOCKED_IPS WHERE IP_ADDRESS = ?", ip);
    }

    public void save(String ip) {
        jdbcTemplate.update("INSERT INTO BLOCKED_IPS (IP_ADDRESS) VALUES (?)", ip);
    }

}

@Repository
class LoginAuditRepository {

    private final static RowMapper<LoginAudit> ROW_MAPPER = (row, num) -> new LoginAudit(
            row.getString("USERNAME"),
            row.getString("IP_ADDRESS"),
            LoginAuditFacade.OperationResult.valueOf(row.getString("RESULT")),
            row.getTimestamp("CREATION_TIMESTAMP").toLocalDateTime()
    );

    private final JdbcTemplate jdbcTemplate;

    LoginAuditRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    List<LoginAudit> findAllByUsername(String username) {
        return jdbcTemplate.query(
                "SELECT USERNAME, IP_ADDRESS, CREATION_TIMESTAMP, RESULT FROM LOG_IN_AUDITS WHERE USERNAME = ? ORDER BY CREATION_TIMESTAMP DESC",
                ROW_MAPPER,
                username
        );
    }

    List<LoginAudit> findFirst4ByUsername(String username) {
        return jdbcTemplate.query(
                "SELECT USERNAME, IP_ADDRESS, CREATION_TIMESTAMP, RESULT FROM LOG_IN_AUDITS WHERE USERNAME = ? ORDER BY CREATION_TIMESTAMP DESC LIMIT 4",
                ROW_MAPPER,
                username
        );
    }

    List<LoginAudit> findFirst4ByIpAddress(String username) {
        return jdbcTemplate.query(
                "SELECT USERNAME, IP_ADDRESS, CREATION_TIMESTAMP, RESULT FROM LOG_IN_AUDITS WHERE IP_ADDRESS = ? ORDER BY CREATION_TIMESTAMP DESC LIMIT 4",
                ROW_MAPPER,
                username
        );
    }

    public void save(String username, String remoteAddress, LoginAuditFacade.OperationResult operationResult, LocalDateTime localDateTime) {
        jdbcTemplate.update(
                "INSERT INTO LOG_IN_AUDITS (USERNAME, IP_ADDRESS, CREATION_TIMESTAMP, RESULT) VALUES (?, ?, ?, ?)",
                username,
                remoteAddress,
                Timestamp.valueOf(localDateTime),
                operationResult.name());
    }
}

