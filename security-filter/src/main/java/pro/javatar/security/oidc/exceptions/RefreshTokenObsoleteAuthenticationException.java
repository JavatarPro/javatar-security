package pro.javatar.security.oidc.exceptions;

import org.springframework.http.HttpStatus;

public class RefreshTokenObsoleteAuthenticationException extends AuthenticationException {

    public RefreshTokenObsoleteAuthenticationException() {
        code = "401RefreshTokenObsolete";
        status = HttpStatus.UNAUTHORIZED;
        message = "Please re-login, provide not obsolete bearer token in jwt format in Authorization header.";
        devMessage = "Both bearer tokens are obsolete.";
    }

    public RefreshTokenObsoleteAuthenticationException(String message) {
        super(message);
    }

    public RefreshTokenObsoleteAuthenticationException(String message, String devMessage) {
        super(message, devMessage);
    }
}
