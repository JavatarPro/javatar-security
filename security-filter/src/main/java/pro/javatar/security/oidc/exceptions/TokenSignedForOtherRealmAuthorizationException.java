package pro.javatar.security.oidc.exceptions;

import org.springframework.http.HttpStatus;

public class TokenSignedForOtherRealmAuthorizationException extends AuthenticationException {

    public TokenSignedForOtherRealmAuthorizationException() {
        code = "403TokenSignedForOtherRealm";
        status = HttpStatus.FORBIDDEN;
        message = "Token belongs to other realm, you have no access to this one.";
        devMessage = "Token belongs to other realm, you have no access to this one.";
    }

    public TokenSignedForOtherRealmAuthorizationException(String message) {
        super(message);
    }

    public TokenSignedForOtherRealmAuthorizationException(String message, String devMessage) {
        super(message, devMessage);
    }
}
