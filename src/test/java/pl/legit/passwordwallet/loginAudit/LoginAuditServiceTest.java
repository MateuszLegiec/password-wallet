package pl.legit.passwordwallet.loginAudit;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

class LoginAuditServiceTest {

    private final static String USERNAME = "username";
    private final static String IP_ADDRESS = "ipAddress";

    private LoginAuditFacade loginAuditFacade;

    private void auditsOf(LoginAuditFacade.OperationResult... operationResults){
        for (LoginAuditFacade.OperationResult operationResult : operationResults) {
            try {
                Thread.sleep(1);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            loginAuditFacade.create(USERNAME, IP_ADDRESS, operationResult);
        }
    }


    @BeforeEach
    void init(){
        loginAuditFacade = new LoginAuditFacade(new MockedLoginAuditRepository(), new MockedBlockedIpRepository(), "100", "200", "300");
    }

    @Test
    void testIfUserIsBlockedForFirstDelayAfterTwoUnsuccessfulLogins() throws InterruptedException {
        //when
        auditsOf(LoginAuditFacade.OperationResult.failure, LoginAuditFacade.OperationResult.failure);
        //then
        Thread.sleep(50);
        Assertions.assertTrue(loginAuditFacade.isUserBlocked(USERNAME));
        Thread.sleep(50);
        Assertions.assertFalse(loginAuditFacade.isUserBlocked(USERNAME));
    }

    @Test
    void testIfUserAndIpAreUnlockedAfterTwoUnsuccessfulLoginsAndOneSuccessfulLogin() {
        //when
        auditsOf(LoginAuditFacade.OperationResult.failure, LoginAuditFacade.OperationResult.failure, LoginAuditFacade.OperationResult.success);
        //then
        Assertions.assertFalse(loginAuditFacade.isUserBlocked(USERNAME));
        Assertions.assertFalse(loginAuditFacade.isIpBlocked(IP_ADDRESS));
    }

    @Test
    void testIfUserIsBlockedForSecondDelayAfterThreeUnsuccessfulLogins() throws InterruptedException {
        //when
        auditsOf(LoginAuditFacade.OperationResult.failure, LoginAuditFacade.OperationResult.failure, LoginAuditFacade.OperationResult.failure);
        //then
        Thread.sleep(100);
        Assertions.assertTrue(loginAuditFacade.isUserBlocked(USERNAME));
        Thread.sleep(100);
        Assertions.assertFalse(loginAuditFacade.isUserBlocked(USERNAME));
    }

    @Test
    void testIfUserAndIpAreUnlockedAfterThreeUnsuccessfulLoginsAndOneSuccessfulLogin(){
        //when
        auditsOf(LoginAuditFacade.OperationResult.failure, LoginAuditFacade.OperationResult.failure, LoginAuditFacade.OperationResult.failure, LoginAuditFacade.OperationResult.success);
        //then
        Assertions.assertFalse(loginAuditFacade.isIpBlocked(IP_ADDRESS));
        Assertions.assertFalse(loginAuditFacade.isUserBlocked(USERNAME));
    }

    @Test
    void testIfUserIsBlockedForThirdDelayAfterFourUnsuccessfulLogins() throws InterruptedException {
        //when
        auditsOf(LoginAuditFacade.OperationResult.failure, LoginAuditFacade.OperationResult.failure, LoginAuditFacade.OperationResult.failure, LoginAuditFacade.OperationResult.failure);
        //then
        Thread.sleep(150);
        Assertions.assertTrue(loginAuditFacade.isUserBlocked(USERNAME));
        Thread.sleep(150);
        Assertions.assertFalse(loginAuditFacade.isUserBlocked(USERNAME));
    }

    @Test
    void testIfUserIsUnlockedAfterFourUnsuccessfulLoginsAndOneSuccessfulLogin() {
        //when
        auditsOf(LoginAuditFacade.OperationResult.failure, LoginAuditFacade.OperationResult.failure, LoginAuditFacade.OperationResult.failure, LoginAuditFacade.OperationResult.failure, LoginAuditFacade.OperationResult.success);
        //then
        Assertions.assertFalse(loginAuditFacade.isUserBlocked(USERNAME));
    }

    @Test
    void testIfIpIsBlockedForFirstDelayAfterTwoUnsuccessfulLogins() throws InterruptedException {
        //when
        loginAuditFacade.create("username_1", IP_ADDRESS, LoginAuditFacade.OperationResult.failure);
        loginAuditFacade.create("username_2", IP_ADDRESS, LoginAuditFacade.OperationResult.failure);
        //then
        Thread.sleep(50);
        Assertions.assertTrue(loginAuditFacade.isIpBlocked(IP_ADDRESS));
        Thread.sleep(50);
        Assertions.assertFalse(loginAuditFacade.isIpBlocked(IP_ADDRESS));
    }

    @Test
    void testIfIpIsBlockedForSecondDelayAfterThreeUnsuccessfulLogins() throws InterruptedException {
        //when
        loginAuditFacade.create("username_1", IP_ADDRESS, LoginAuditFacade.OperationResult.failure);
        loginAuditFacade.create("username_2", IP_ADDRESS, LoginAuditFacade.OperationResult.failure);
        loginAuditFacade.create("username_3", IP_ADDRESS, LoginAuditFacade.OperationResult.failure);
        //then
        Thread.sleep(100);
        Assertions.assertTrue(loginAuditFacade.isIpBlocked(IP_ADDRESS));
        Thread.sleep(100);
        Assertions.assertFalse(loginAuditFacade.isIpBlocked(IP_ADDRESS));
    }


    @Test
    void testIfIpIsBlockedPermanentlyAfterFourUnsuccessfulLogins() {
        //when
        loginAuditFacade.create("username_1", IP_ADDRESS, LoginAuditFacade.OperationResult.failure);
        loginAuditFacade.create("username_2", IP_ADDRESS, LoginAuditFacade.OperationResult.failure);
        loginAuditFacade.create("username_3", IP_ADDRESS, LoginAuditFacade.OperationResult.failure);
        loginAuditFacade.create("username_4", IP_ADDRESS, LoginAuditFacade.OperationResult.failure);
        Assertions.assertTrue(loginAuditFacade.isIpBlocked(IP_ADDRESS));
        //then
        Assertions.assertTrue(loginAuditFacade.findAllBlockedIps().contains(IP_ADDRESS));
    }

}

class MockedLoginAuditRepository extends LoginAuditRepository {

    private final List<LoginAudit> audits = new ArrayList<>();

    MockedLoginAuditRepository() {
        super(null);
    }

    @Override
    List<LoginAudit> findAllByUsername(String username) {
        return audits.stream().filter(it -> it.username().equals(username)).collect(Collectors.toList());
    }

    @Override
    public void save(String username, String remoteAddress, LoginAuditFacade.OperationResult operationResult, LocalDateTime localDateTime) {
        audits.add(new LoginAudit(username, remoteAddress, operationResult, localDateTime));
    }

    @Override
    List<LoginAudit> findFirst4ByUsername(String username) {
        return audits.stream()
                .filter(it -> it.username().equals(username))
                .sorted(
                        Comparator
                                .comparing(LoginAudit::creationDate)
                                .reversed()
                )
                .limit(4)
                .collect(Collectors.toList());
    }

    @Override
    List<LoginAudit> findFirst4ByIpAddress(String ip) {
        return audits.stream()
                .filter(it -> it.ipAddress().equals(ip))
                .sorted(
                        Comparator
                                .comparing(LoginAudit::creationDate)
                                .reversed()
                )
                .limit(4)
                .collect(Collectors.toList());
    }
}

class MockedBlockedIpRepository extends BlockedIpRepository {

    private final Set<String> ips = new HashSet<>();

    MockedBlockedIpRepository() {
        super(null);
    }

    @Override
    public List<String> findAll() {
        return ips.stream().toList();
    }

    @Override
    public Optional<String> findById(String ip) {
        return ips.contains(ip) ? Optional.of(ip) : Optional.empty();
    }

    @Override
    public void deleteById(String ip) {
        ips.remove(ip);
    }

    @Override
    public void save(String ip) {
        ips.add(ip);
    }

}
