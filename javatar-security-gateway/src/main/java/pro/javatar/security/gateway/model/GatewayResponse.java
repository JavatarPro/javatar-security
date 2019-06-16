package pro.javatar.security.gateway.model;

import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Borys Zora
 * @version 2019-06-16
 */
public class GatewayResponse {

    private Map<String, Object> responseGatewayHeaders = new HashMap<>();

    private HttpServletResponse response;

    public Map<String, Object> getResponseGatewayHeaders() {
        return responseGatewayHeaders;
    }

    public void setResponseGatewayHeaders(Map<String, Object> responseGatewayHeaders) {
        this.responseGatewayHeaders = responseGatewayHeaders;
    }

    public GatewayResponse withResponseGatewayHeaders(Map<String, Object> responseGatewayHeaders) {
        this.responseGatewayHeaders = responseGatewayHeaders;
        return this;
    }

    public HttpServletResponse getResponse() {
        return response;
    }

    public void setResponse(HttpServletResponse response) {
        this.response = response;
    }

    public GatewayResponse withResponse(HttpServletResponse response) {
        this.response = response;
        return this;
    }

    @Override
    public String toString() {
        return "GatewayResponse{" +
                "responseGatewayHeaders=" + responseGatewayHeaders +
                ", response=" + response +
                '}';
    }
}
