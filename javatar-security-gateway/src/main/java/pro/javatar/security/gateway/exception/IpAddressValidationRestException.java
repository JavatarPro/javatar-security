package pro.javatar.security.gateway.exception;

/**
 * TODO status code 403
 * @author Borys Zora
 * @version 2019-07-23
 */
public class IpAddressValidationRestException extends GatewayRestException {

    public IpAddressValidationRestException(String message) {
        super(message);
        l18Code = "";
    }
}
