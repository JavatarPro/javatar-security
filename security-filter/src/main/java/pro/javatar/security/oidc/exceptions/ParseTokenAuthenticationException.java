package pro.javatar.security.oidc.exceptions;

import org.springframework.http.HttpStatus;

public class ParseTokenAuthenticationException extends AuthenticationException {

    public ParseTokenAuthenticationException() {
        code = "403_ParseTokenAuthenticationException";
        status = HttpStatus.FORBIDDEN;
        message = "Could not parse jwt token obtained from identity provider.";
        devMessage = "Could not parse jwt token obtained from identity provider.";
    }

}
