package pro.javatar.security.oidc.exceptions;

import org.springframework.http.HttpStatus;

public class RealmNotFoundAuthenticationException extends AuthenticationException {

    public RealmNotFoundAuthenticationException() {
        code = "401RealmNotFound";
        status = HttpStatus.UNAUTHORIZED;
        message = "Please provide your realm.";
        devMessage = "User unique in scope of realm.";
    }

    public RealmNotFoundAuthenticationException(String message) {
        super(message);
    }

    public RealmNotFoundAuthenticationException(String message, String devMessage) {
        super(message, devMessage);
    }
}
