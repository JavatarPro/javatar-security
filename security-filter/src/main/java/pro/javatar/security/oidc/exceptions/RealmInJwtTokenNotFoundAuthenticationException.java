package pro.javatar.security.oidc.exceptions;

import org.springframework.http.HttpStatus;

public class RealmInJwtTokenNotFoundAuthenticationException extends AuthenticationException {

    public RealmInJwtTokenNotFoundAuthenticationException() {
        code = "401RealmInJwtTokenNotFound";
        status = HttpStatus.UNAUTHORIZED;
        message = "Token is not valid, could not recognize to which realm it belongs.";
        devMessage = "Token is not valid, could not recognize to which realm it belongs.";
    }

    public RealmInJwtTokenNotFoundAuthenticationException(String message) {
        super(message);
    }

    public RealmInJwtTokenNotFoundAuthenticationException(String message, String devMessage) {
        super(message, devMessage);
    }
}
