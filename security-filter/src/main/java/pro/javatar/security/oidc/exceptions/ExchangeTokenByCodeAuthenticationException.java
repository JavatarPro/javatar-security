package pro.javatar.security.oidc.exceptions;

import org.springframework.http.HttpStatus;

public class ExchangeTokenByCodeAuthenticationException extends AuthenticationException {

    public ExchangeTokenByCodeAuthenticationException() {
        code = "401ExchangeTokenByCode";
        status = HttpStatus.UNAUTHORIZED;
        message = "Could not exchange token by authorization code.";
        devMessage = "Provide reason of could not exchange token by authorization code.";
    }

    public ExchangeTokenByCodeAuthenticationException(String message) {
        super(message);
    }

    public ExchangeTokenByCodeAuthenticationException(String message, String devMessage) {
        super(message, devMessage);
    }
}
