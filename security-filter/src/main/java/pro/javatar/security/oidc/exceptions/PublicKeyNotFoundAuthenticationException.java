package pro.javatar.security.oidc.exceptions;

import org.springframework.http.HttpStatus;

public class PublicKeyNotFoundAuthenticationException extends AuthenticationException {

    public PublicKeyNotFoundAuthenticationException() {
        code = "401PublicKeyNotFound";
        status = HttpStatus.UNAUTHORIZED;
        message = "Could not retrieve public key from cache.";
        devMessage = "Public key is not found in cache.";
    }

    public PublicKeyNotFoundAuthenticationException(String message) {
        super(message);
    }

    public PublicKeyNotFoundAuthenticationException(String message, String devMessage) {
        super(message, devMessage);
    }
}
