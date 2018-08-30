package pro.javatar.security.jwt.exception;

public class Base64UtilException extends RuntimeException {

    public Base64UtilException() {
    }

    public Base64UtilException(String message) {
        super(message);
    }

    public Base64UtilException(String message, Throwable cause) {
        super(message, cause);
    }
}
