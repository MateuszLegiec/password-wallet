package pl.legit.passwordwallet;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import pl.legit.passwordwallet.loginAudit.LoginAuditFacade;
import pl.legit.passwordwallet.users.UsersService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Set;

@Configuration
class SecurityConfig implements WebMvcConfigurer {

    @Autowired
    UsersService usersService;
    @Autowired
    LoginAuditFacade loginAuditFacade;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new SecurityInterceptor(usersService, loginAuditFacade));
    }
}

record SecurityInterceptor(UsersService usersService, LoginAuditFacade loginAuditFacade) implements HandlerInterceptor {

    private final static Set<String> whiteList = Set.of(
            "/",
            "/index.html",
            "/functions.js",
            "/registration.html",
            "/favicon.ico",
            "/error",
            "/register",
            "/wallet.html",
            "/subject-wallet.html"
    );

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        if (!whiteList.contains(request.getRequestURI())) {
            final CredentialsDTO authorization = SecurityUtils.decodeToken(request.getHeader("Authorization"));
            if (loginAuditFacade.isIpBlocked(request.getRemoteAddr()) || loginAuditFacade.isUserBlocked(authorization.getUsername())){
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
            }
            try {
                usersService.authenticate(authorization.getUsername(), authorization.getPassword());
                createAuditIfUriEqualsLogin(request.getRequestURI(), authorization.getUsername(), request.getRemoteAddr(), LoginAuditFacade.OperationResult.success);
            } catch (IllegalArgumentException | EmptyResultDataAccessException | ResponseStatusException e){
                createAuditIfUriEqualsLogin(request.getRequestURI(), authorization.getUsername(), request.getRemoteAddr(), LoginAuditFacade.OperationResult.failure);
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
            }
        }
        return HandlerInterceptor.super.preHandle(request, response, handler);
    }

    void createAuditIfUriEqualsLogin(String uri, String username, String remoteAddress, LoginAuditFacade.OperationResult operation){
        if (uri.equals("/login")){
            loginAuditFacade.create(username, remoteAddress, operation);
        }
    }
}

class SecurityUtils{
    static CredentialsDTO decodeToken(String authorizationHeader){
        final var decode = new String(Base64.getDecoder().decode(authorizationHeader.substring(6)), StandardCharsets.UTF_8).split(":");
        return new CredentialsDTO(decode[0], decode[1]);
    }
}
