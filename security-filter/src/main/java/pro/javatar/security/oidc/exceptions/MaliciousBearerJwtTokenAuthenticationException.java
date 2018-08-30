package pro.javatar.security.oidc.exceptions;

import org.springframework.http.HttpStatus;

public class MaliciousBearerJwtTokenAuthenticationException extends AuthenticationException {

    public MaliciousBearerJwtTokenAuthenticationException() {
        code = "401MaliciousBearerJwtToken";
        status = HttpStatus.UNAUTHORIZED;
        message = "Application can not authenticate you.";
        devMessage = "Malicious user made his attack";
    }

    public MaliciousBearerJwtTokenAuthenticationException(String message) {
        super(message);
    }

    public MaliciousBearerJwtTokenAuthenticationException(String message, String devMessage) {
        super(message, devMessage);
    }

}
