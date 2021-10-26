package pl.legit.passwordwallet;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Set;

@Configuration
class SecurityConfig implements WebMvcConfigurer {

    @Autowired
    ApplicationService applicationService;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new SecurityInterceptor(applicationService));
    }
}

record SecurityInterceptor(ApplicationService applicationService) implements HandlerInterceptor {

    private final static Set<String> whiteList = Set.of(
            "/",
            "/index.html",
            "/functions.js",
            "/registration.html",
            "/favicon.ico",
            "/error",
            "/register",
            "/wallet.html"
    );

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        if (!whiteList.contains(request.getRequestURI())) {
            try {
                final CredentialsDTO authorization = SecurityUtils.decodeToken(request.getHeader("Authorization"));
                applicationService.authenticate(authorization.getUsername(), authorization.getPassword());
            } catch (IllegalArgumentException | EmptyResultDataAccessException e){
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
            }
        }
        return HandlerInterceptor.super.preHandle(request, response, handler);
    }
}

class SecurityUtils{
    static CredentialsDTO decodeToken(String authorizationHeader){
        final var decode = new String(Base64.getDecoder().decode(authorizationHeader.substring(6)), StandardCharsets.UTF_8).split(":");
        return new CredentialsDTO(decode[0], decode[1]);
    }
}
