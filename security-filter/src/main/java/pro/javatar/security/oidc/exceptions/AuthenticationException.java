package pro.javatar.security.oidc.exceptions;

import org.springframework.http.HttpStatus;

public class AuthenticationException extends RuntimeException {

    protected String code;

    protected HttpStatus status;

    protected String devMessage;

    protected String message;

    protected String link;

    public AuthenticationException() {
        code = "401Common";
        status = HttpStatus.UNAUTHORIZED;
        message = "";
        devMessage = "";
    }

    public AuthenticationException(String message) {
        this();
        this.message = message;
    }

    public AuthenticationException(String message, String devMessage) {
        this(message);
        this.devMessage = devMessage;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public void setStatus(HttpStatus status) {
        this.status = status;
    }

    public String getDevMessage() {
        return devMessage;
    }

    public void setDevMessage(String devMessage) {
        this.devMessage = devMessage;
    }

    @Override
    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getLink() {
        return link;
    }

    public void setLink(String link) {
        this.link = link;
    }
}
