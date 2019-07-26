package pro.javatar.security.gateway.exception;

import org.springframework.http.HttpStatus;

/**
 * Common gateway exception.
 * More specific exceptions should extend it and override properties if needed
 *
 * @author Borys Zora
 * @version 2019-06-01
 */
public class GatewayRestException extends RuntimeException {

    protected String devMessage;

    protected HttpStatus status = HttpStatus.FORBIDDEN;

    protected String code;

    protected String l18Code;

    public GatewayRestException(String message) {
        super(message);
    }

    public String getDevMessage() {
        return devMessage;
    }

    public void setDevMessage(String devMessage) {
        this.devMessage = devMessage;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public void setStatus(HttpStatus status) {
        this.status = status;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getL18Code() {
        return l18Code;
    }

    public void setL18Code(String l18Code) {
        this.l18Code = l18Code;
    }

    @Override
    public String toString() {
        return "GatewayRestException{" +
                "devMessage='" + devMessage + '\'' +
                ", status=" + status +
                ", code='" + code + '\'' +
                ", l18Code='" + l18Code + '\'' +
                '}';
    }
}
