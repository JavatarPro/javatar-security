package pro.javatar.security.starter.config;

/**
 * @author Borys Zora
 * @version 2019-05-13
 */
public class ConfigValidationException extends RuntimeException {

    public ConfigValidationException(String message) {
        super(message);
    }
}
