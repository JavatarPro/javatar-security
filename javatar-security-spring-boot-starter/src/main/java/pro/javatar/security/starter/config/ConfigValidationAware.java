package pro.javatar.security.starter.config;

/**
 * @author Borys Zora
 * @version 2019-05-13
 */
public interface ConfigValidationAware {

    void validateConfiguration() throws ConfigValidationException;

}
