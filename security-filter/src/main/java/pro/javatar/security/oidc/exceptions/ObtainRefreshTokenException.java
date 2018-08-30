package pro.javatar.security.oidc.exceptions;

import org.springframework.http.HttpStatus;

public class ObtainRefreshTokenException extends AuthenticationException {

    public ObtainRefreshTokenException() {
        code = "401RefreshTokenError";
        status = HttpStatus.UNAUTHORIZED;
        message = "Please check parameters for token refresh";
        devMessage = "Refresh token error.";
    }

    public ObtainRefreshTokenException(String message) {
        super(message);
    }

    public ObtainRefreshTokenException(String message, String devMessage) {
        super(message, devMessage);
    }

}
