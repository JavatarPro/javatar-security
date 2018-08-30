package pro.javatar.security.oidc.exceptions;

import org.springframework.http.HttpStatus;

public class BearerJwtTokenNotFoundAuthenticationException extends AuthenticationException {

    public BearerJwtTokenNotFoundAuthenticationException() {
        code = "401BearerJwtTokenNotFound";
        status = HttpStatus.UNAUTHORIZED;
        message = "Please provide bearer token in jwt format in Authorization header.";
        devMessage = "Bearer not found.";
    }

    public BearerJwtTokenNotFoundAuthenticationException(String message) {
        super(message);
    }

    public BearerJwtTokenNotFoundAuthenticationException(String message, String devMessage) {
        super(message, devMessage);
    }

}
