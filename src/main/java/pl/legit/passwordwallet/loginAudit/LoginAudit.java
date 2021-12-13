package pl.legit.passwordwallet.loginAudit;

import java.time.LocalDateTime;

public record LoginAudit(String username, String ipAddress, LoginAuditFacade.OperationResult operationResult, LocalDateTime creationDate) { }
