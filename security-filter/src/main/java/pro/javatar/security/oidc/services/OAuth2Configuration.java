package pro.javatar.security.oidc.services;

import pro.javatar.security.oidc.utils.UrlResolver;

import java.io.UnsupportedEncodingException;
import java.util.List;

public interface OAuth2Configuration {

    boolean isJwtBearerFilterEnable();

    void setJwtBearerFilterEnable(boolean jwtBearerFilterEnable);

    boolean isJwtBearerTokenRequired();

    void setJwtBearerTokenRequired(boolean jwtBearerTokenRequired);

    void setFilterApplyUrlList(List<String> filterApplyUrlList);

    void setFilterIgnoreUrlList(List<String> filterIgnoreUrlList);

    void setFilterApplyUrlRegex(String filterApplyUrlRegex);

    String getIdentityProviderHost();

    void setIdentityProviderHost(String identityProviderHost);

    String getAuthorizationEndpoint();

    void setAuthorizationEndpoint(String authorizationEndpoint);

    String getTokenEndpoint();

    void setTokenEndpoint(String tokenEndpoint);

    String getClientId();

    void setClientId(String clientId);

    String getClientSecret();

    void setClientSecret(String clientSecret);

    String buildRedirectUrl(String realm, String redirectUrl) throws UnsupportedEncodingException;

    String getScope();

    void setScope(String scope);

    String getUsername();

    void setUsername(String username);

    String getUserPassword();

    void setUserPassword(String userPassword);

    boolean isCheckIsActive();

    void setCheckIsActive(boolean checkIsActive);

    boolean isCheckTokenType();

    void setCheckTokenType(boolean checkTokenType);

    String getDefaultRealm();

    void setDefaultRealm(String defaultRealm);

    void addRunOnBehalfOfUsers(String username, String userPassword, String realm);

    void setRunOnBehalfOfUsers(String credentials);

    UrlResolver getInterceptorUrlResolver();

    UrlResolver getUrlResolver();

}
