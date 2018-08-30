package pro.javatar.security.oidc.exceptions;

import org.springframework.http.HttpStatus;

public class ExpiredAuthenticationSessionException extends AuthenticationException {

    public ExpiredAuthenticationSessionException() {
        code = "401SessionExpired";
        status = HttpStatus.UNAUTHORIZED;
        message = "Request session is already expired.";
        devMessage = "Request session is already expired.";
    }

    public ExpiredAuthenticationSessionException(String message) {
        super(message);
    }

    public ExpiredAuthenticationSessionException(String message, String devMessage) {
        super(message, devMessage);
    }
}
