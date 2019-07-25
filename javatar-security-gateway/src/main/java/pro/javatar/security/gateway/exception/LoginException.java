package pro.javatar.security.gateway.exception;

/**
 * TODO improve, throw different exception depends on what cause the issue
 *   make exceptions more granular
 * @author Borys Zora
 * @version 2019-06-01
 */
public class LoginException extends GatewayRestException {

    public LoginException(String message) {
        super(message);
    }

}
