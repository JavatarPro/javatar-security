package pro.javatar.security.oidc;

public interface SecurityConstants {

    String REALM_HEADER = "X-REALM";

    String REFERER_HEADER = "referer";

    String REFRESH_TOKEN_HEADER = "X-Refresh-Token";

    String LOGOUT_URL_HEADER = "X-Logout-URL";

    String ERROR = "error";

    String ERROR_DESCRIPTION = "error_description";

    String INVALID_GRANT = "invalid_grant";

    String X_CORRELATION_ID = "X-Correlation-ID";
}
