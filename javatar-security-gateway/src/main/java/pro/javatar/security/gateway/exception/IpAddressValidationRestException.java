package pro.javatar.security.gateway.exception;

/**
 * @author Borys Zora
 * @version 2019-07-23
 */
public class IpAddressValidationRestException extends GatewayRestException {

    public IpAddressValidationRestException(String message) {
        super(message);
        code = "403";
        devMessage = "token was issued to different ip address, potential attack with stolen token or vpn switch";
        l18Code = "403.access.denied.wrong.ipAddress";
    }
}
