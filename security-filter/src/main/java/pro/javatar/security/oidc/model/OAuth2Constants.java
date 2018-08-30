package pro.javatar.security.oidc.model;

public interface OAuth2Constants {

    String CODE = "code";

    String CLIENT_ID = "client_id";

    String CLIENT_SECRET = "client_secret";

    String ERROR = "error";

    String ERROR_DESCRIPTION = "error_description";

    String REDIRECT_URI = "redirect_uri";

    String SCOPE = "scope";

    String STATE = "state";

    String GRANT_TYPE = "grant_type";

    String RESPONSE_TYPE = "response_type";

    String ACCESS_TOKEN = "access_token";

    String ID_TOKEN = "id_token";

    String REFRESH_TOKEN = "refresh_token";

    String EXPIRES_IN = "expires_in";

    String REFRESH_EXPIRES_IN = "refresh_expires_in";

    String AUTHORIZATION_CODE = "authorization_code";

    String IMPLICIT = "implicit";

    String USERNAME = "username";

    // NOSONAR
    String PASSWORD = "password";

    String CLIENT_CREDENTIALS = "client_credentials";

    // https://tools.ietf.org/html/draft-ietf-oauth-assertions-01#page-5
    String CLIENT_ASSERTION_TYPE = "client_assertion_type";
    String CLIENT_ASSERTION = "client_assertion";

    // https://tools.ietf.org/html/draft-jones-oauth-jwt-bearer-03#section-2.2
    String CLIENT_ASSERTION_TYPE_JWT = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    // http://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess
    String OFFLINE_ACCESS = "offline_access";

    // http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
    String SCOPE_OPENID = "openid";

    // http://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
    String SCOPE_PROFILE = "profile";
    String SCOPE_EMAIL = "email";
    String SCOPE_ADDRESS = "address";
    String SCOPE_PHONE = "phone";

    String UI_LOCALES_PARAM = "ui_locales";

    String PROMPT = "prompt";

    String MAX_AGE = "max_age";

    String JWT = "JWT";

}


