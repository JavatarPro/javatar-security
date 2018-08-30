package pro.javatar.security.oidc.exceptions;

import org.springframework.http.HttpStatus;

public class ObtainTokenByUserCredentialAuthenticationException extends AuthenticationException {

    public ObtainTokenByUserCredentialAuthenticationException() {
        code = "401ObtainTokenByUserCredentialAuthenticationException";
        status = HttpStatus.UNAUTHORIZED;
        message = "Could not obtain token by user credentials.";
        devMessage = "todo provide reason of could not exchange token by user credentials";
    }

    public ObtainTokenByUserCredentialAuthenticationException(String message) {
        super(message);
    }

    public ObtainTokenByUserCredentialAuthenticationException(String message, String devMessage) {
        super(message, devMessage);
    }
}
