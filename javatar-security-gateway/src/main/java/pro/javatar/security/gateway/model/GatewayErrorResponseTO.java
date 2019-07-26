package pro.javatar.security.gateway.model;

import java.time.Instant;

/**
 * @author Borys Zora
 * @version 2019-07-24
 */
public class GatewayErrorResponseTO {

    private String code;

    private String status;

    private String message;

    private String devMessage;

    private Instant dateTime;

    private String l18Code;

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getDevMessage() {
        return devMessage;
    }

    public void setDevMessage(String devMessage) {
        this.devMessage = devMessage;
    }

    public Instant getDateTime() {
        return dateTime;
    }

    public void setDateTime(Instant dateTime) {
        this.dateTime = dateTime;
    }

    public String getL18Code() {
        return l18Code;
    }

    public void setL18Code(String l18Code) {
        this.l18Code = l18Code;
    }

    @Override
    public String toString() {
        return "GatewayErrorResponseTO{" +
                "code='" + code + '\'' +
                ", status='" + status + '\'' +
                ", message='" + message + '\'' +
                ", devMessage='" + devMessage + '\'' +
                ", dateTime=" + dateTime +
                ", l18Code='" + l18Code + '\'' +
                '}';
    }
}
