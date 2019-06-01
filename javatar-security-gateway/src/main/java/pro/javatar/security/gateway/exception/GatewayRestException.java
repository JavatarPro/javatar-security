package pro.javatar.security.gateway.exception;

/**
 * @author Borys Zora
 * @version 2019-06-01
 */
public class GatewayRestException extends RuntimeException {

    public GatewayRestException() {
    }

    public GatewayRestException(String message) {
        super(message);
    }
}
