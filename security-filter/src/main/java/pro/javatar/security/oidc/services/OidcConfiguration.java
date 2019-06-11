package pro.javatar.security.oidc.services;

import pro.javatar.security.oidc.model.UserKey;
import pro.javatar.security.oidc.utils.StringUtils;
import pro.javatar.security.oidc.utils.UrlResolver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

// TODO rename OidcEndpoints
@Service
public class OidcConfiguration implements OAuth2Configuration, InitializingBean {

    private static final Logger logger = LoggerFactory.getLogger(OidcConfiguration.class);

    public static final String REDIRECT_URI_PLACEHOLDER = "{redirect_uri}";
    public static final String CLIENT_ID_PLACEHOLDER = "{client_id}";
    public static final String REALM_PLACEHOLDER = "{realm}";
    public static final String TOKEN_ENDPOINT =
            "/auth/realms/" + REALM_PLACEHOLDER + "/protocol/openid-connect/token";
    public static final String LOGOUT_ENDPOINT =
            "/auth/realms/" + REALM_PLACEHOLDER + "/protocol/openid-connect/logout?redirect_uri=";
    public static final String AUTHORIZATION_ENDPOINT = "/auth/realms/" + REALM_PLACEHOLDER
            + "/protocol/openid-connect/auth?client_id=" + CLIENT_ID_PLACEHOLDER + "&redirect_uri="
            + REDIRECT_URI_PLACEHOLDER + "&response_type=code&scope=openid";

    @Value("${security.oidc.identity_provider_host:}")
    private String identityProviderHost;

    @Value("${security.oidc.authorization_endpoint:" + AUTHORIZATION_ENDPOINT + "}")
    private String authorizationEndpoint;

    @Value("${security.oidc.logout_endpoint:" + LOGOUT_ENDPOINT + "}")
    private String logoutEndpoint;

    @Value("${security.oidc.token_endpoint:" + TOKEN_ENDPOINT + "}")
    private String tokenEndpoint;

    @Value("${security.oauth2.client_id:}")
    private String clientId;

    @Value("${security.oauth2.client_secret:}")
    private String clientSecret;

    @Value("${security.oauth2.username:}")
    private String username;

    @Value("${security.oauth2.password:}")
    private String userPassword;

    private Map<UserKey, String> runOnBehalfOfUsers = new ConcurrentHashMap<>();

    @Value("${security.oidc.encodeRedirectUri:true}")
    private boolean encodeRedirectUri = true;

    @Value("${security.oidc.skipRefererCheck:false}")
    private boolean skipRefererCheck = false;

    @Value("${security.cors.enable:false}")
    private boolean corsFilterEnable = false;

    private String scope;

    @Value("${security.oidc.checkTokenIsActive:true}")
    public boolean checkIsActive;

    @Value("${security.oidc.checkTokenType:true}")
    public boolean checkTokenType;

    @Value("${security.oidc.useReferAsRedirectUri:false}")
    public boolean useReferAsRedirectUri;

    @Value("${security.oidc.defaultRealm:mservice}")
    public String defaultRealm;

    @Value("${security.oauth2.tokenShouldBeRefreshed:75}")
    private int tokenShouldBeRefreshed;

    @Value("${security.oidc.excludeValidationRealm:mservice}")
    public String excludeValidationRealm;

    @Value("${security.oidc.OidcAuthenticationHttpClientInterceptor.enable:true}")
    public boolean securityInterceptorEnable;

    private final FilterOptionConverter filterOptionConverter = new FilterOptionConverter();
    private final UrlResolver interceptorUrlResolver = new UrlResolver();
    private final UrlResolver urlResolver = new UrlResolver();

    @Value("${security.oidc.OidcAuthenticationHttpClientInterceptor.applyUrlRegex:/.*}")
    public void setSecurityInterceptorApplyUrlRegex(String applyUrlRegex) {
        interceptorUrlResolver.setFilterApplyUrlRegex(applyUrlRegex);
    }

    @Value("#{'${security.oidc.OidcAuthenticationHttpClientInterceptor.filterApplyUrlList:}'.split(',')}")
    public void setSecurityInterceptorApplyUrlList(List<String> filterApplyUrlList) {
        this.interceptorUrlResolver.setFilterApplyUrls(filterOptionConverter.convertList(filterApplyUrlList));
    }

    @Override
    public UrlResolver getInterceptorUrlResolver() {
        return interceptorUrlResolver;
    }

    @Override
    public UrlResolver getUrlResolver() {
        return urlResolver;
    }

    @Deprecated // Do not use regex in future, use simple construction
    @Override
    // @Value("${security.oidc.filterApplyUrlRegex:\\/.*}")
    public void setFilterApplyUrlRegex(String filterApplyUrlRegex) {
        urlResolver.setFilterApplyUrlRegex(filterApplyUrlRegex);
    }

    @Override
    @Value("#{'${security.oidc.filterApplyUrlList:}'.split(',')}")
    public void setFilterApplyUrlList(List<String> filterApplyUrlList) {
        urlResolver.setFilterApplyUrls(filterOptionConverter.convertList(filterApplyUrlList));
    }

    @Override
    @Value("#{'${security.oidc.filterIgnoreUrlList:}'.split(',')}")
    public void setFilterIgnoreUrlList(List<String> filterIgnoreUrlList) {
        urlResolver.setFilterIgnoreUrls(filterOptionConverter.convertList(filterIgnoreUrlList));
    }

    @Value("${security.oidc.AuthenticationJwtBearerTokenAwareFilter.enable:true}")
    private boolean jwtBearerFilterEnable = false;

    @Value("${security.oidc.AuthenticationJwtBearerTokenAwareFilter.anonymousAllowed:false}")
    private boolean anonymousAllowed = false;

    @Value("${security.oidc.AuthenticationJwtBearerTokenAwareFilter.jwtBearerTokenRequired:true}")
    private boolean jwtBearerTokenRequired = true;

    // @Value("${security.oidc.AuthenticationJwtBearerTokenAwareFilter.jwtBearerTokenOtherAuthenticationAllowed:false}")
    private boolean jwtBearerTokenOtherAuthenticationAllowed = false;

    public boolean isCorsFilterEnable() {
        return corsFilterEnable;
    }

    public void setCorsFilterEnable(boolean corsFilterEnable) {
        this.corsFilterEnable = corsFilterEnable;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        if (StringUtils.isBlank(username)) {
            logger.warn("default username must be specified for cases when you run on behalf of application user");
        } else if (StringUtils.isNotBlank(userPassword)) { // add default user to map if password specified
            addRunOnBehalfOfUsers(username, userPassword, defaultRealm);
        } else {
            if (StringUtils.isBlank(runOnBehalfOfUsers.get(username))) {
                throw new IllegalStateException("password for default user: " + username + " must be specified");
            }
        }
    }

    @Override
    public boolean isJwtBearerFilterEnable() {
        return jwtBearerFilterEnable;
    }

    @Override
    public void setJwtBearerFilterEnable(boolean jwtBearerFilterEnable) {
        this.jwtBearerFilterEnable = jwtBearerFilterEnable;
    }

    @Override
    public boolean isJwtBearerTokenRequired() {
        return jwtBearerTokenRequired;
    }

    @Override
    public void setJwtBearerTokenRequired(boolean jwtBearerTokenRequired) {
        this.jwtBearerTokenRequired = jwtBearerTokenRequired;
    }

    // use SecurityConfig
    @Deprecated
    @Override
    public String getIdentityProviderHost() {
        return identityProviderHost;
    }

    // use SecurityConfig
    @Deprecated
    @Override
    public void setIdentityProviderHost(String identityProviderHost) {
        this.identityProviderHost = identityProviderHost;
    }

    @Override
    public String getAuthorizationEndpoint() {
        return authorizationEndpoint;
    }

    @Override
    public void setAuthorizationEndpoint(String authorizationEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
    }

    @Override
    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    @Override
    public void setTokenEndpoint(String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    // use SecurityConfig
    @Deprecated
    @Override
    public String getClientId() {
        return clientId;
    }

    // use SecurityConfig
    @Deprecated
    @Override
    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    // use SecurityConfig
    @Deprecated
    @Override
    public String getClientSecret() {
        return clientSecret;
    }

    // use SecurityConfig
    @Deprecated
    @Override
    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    @Override
    public String buildRedirectUrl(String realm, String redirectUrl) throws UnsupportedEncodingException {
        String redirectUri =
                encodeRedirectUri ? URLEncoder.encode(redirectUrl, "UTF-8") : redirectUrl;
        String endpointUri = replaceRealPlaceHolder(realm, authorizationEndpoint);
        return identityProviderHost +
                endpointUri.
                        replace(CLIENT_ID_PLACEHOLDER, clientId).
                        replace(REDIRECT_URI_PLACEHOLDER, redirectUri);
    }

    private String replaceRealPlaceHolder(String realm, String redirectUri) {
        return redirectUri.replace(REALM_PLACEHOLDER, realm != null ? realm : "");
    }

    String buildLogoutUrl(String realm) {
        String logoutUri = this.logoutEndpoint;
        logoutUri = replaceRealPlaceHolder(realm, logoutUri);
        return identityProviderHost + logoutUri;
    }

    @Override
    public String getScope() {
        return scope;
    }

    @Override
    public void setScope(String scope) {
        this.scope = scope;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public String getUserPassword() {
        return userPassword;
    }

    @Override
    public void setUserPassword(String userPassword) {
        this.userPassword = userPassword;
    }

    @Override
    public boolean isCheckIsActive() {
        return checkIsActive;
    }

    @Override
    public void setCheckIsActive(boolean checkIsActive) {
        this.checkIsActive = checkIsActive;
    }

    @Override
    public boolean isCheckTokenType() {
        return checkTokenType;
    }

    @Override
    public void setCheckTokenType(boolean checkTokenType) {
        this.checkTokenType = checkTokenType;
    }

    @Override
    public String getDefaultRealm() {
        return this.defaultRealm;
    }

    @Override
    public void setDefaultRealm(String defaultRealm) {
        this.defaultRealm = defaultRealm;
    }

    public String getExcludeValidationRealm() {
        return excludeValidationRealm;
    }

    public void setExcludeValidationRealm(String excludeValidationRealm) {
        this.excludeValidationRealm = excludeValidationRealm;
    }

    public boolean isUseReferAsRedirectUri() {
        return useReferAsRedirectUri;
    }

    public void setUseReferAsRedirectUri(boolean useReferAsRedirectUri) {
        this.useReferAsRedirectUri = useReferAsRedirectUri;
    }

    public boolean isSecurityInterceptorEnable() {
        return securityInterceptorEnable;
    }

    public int getTokenShouldBeRefreshed() {
        return tokenShouldBeRefreshed;
    }

    public boolean isEncodeRedirectUri() {
        return encodeRedirectUri;
    }

    public void setEncodeRedirectUri(boolean encodeRedirectUri) {
        this.encodeRedirectUri = encodeRedirectUri;
    }

    @Value("${security.oidc.AuthenticationJwtBearerTokenAwareFilter.jwtBearerTokenOtherAuthenticationAllowed:false}")
    public void setJwtBearerTokenOtherAuthenticationAllowed(boolean jwtBearerTokenOtherAuthenticationAllowed) {
        this.jwtBearerTokenOtherAuthenticationAllowed = jwtBearerTokenOtherAuthenticationAllowed;
    }

    public boolean isJwtBearerTokenOtherAuthenticationAllowed() {
        return jwtBearerTokenOtherAuthenticationAllowed;
    }

    // TODO move it security config
    @Deprecated
    public String getRunOnBehalfOfUserPassword(String username, String realm) {
        UserKey userKey = new UserKey(username, realm);
        return runOnBehalfOfUsers.get(userKey);
    }

    public Map<UserKey, String> getRunOnBehalfOfUsers() {
        return Collections.unmodifiableMap(runOnBehalfOfUsers);
    }

    public void addRunOnBehalfOfUsers(String username, String userPassword, String realm){
        UserKey userKey = new UserKey(username, realm);
        logger.info("added credentials to run on behalf for user: {}", userKey);
        runOnBehalfOfUsers.put(userKey, userPassword);
    }

    /**
     * Sets runOnBehalf user for exact realm
     * @param credentials format login:password@realm (e.g. admin:wtqwerty@test-qa-rc)
     */
    @Override
    @Value("${security.oauth2.runOnBehalfOfUser:}")
    public void setRunOnBehalfOfUsers(String credentials) {
        if (StringUtils.isBlank(credentials)) {
            return;
        }
        String[] usersCredentials = credentials.split(",");
        for (String usersCredential: usersCredentials) {
            addUserToRunOnBehalfMap(usersCredential);
        }
    }

    void addUserToRunOnBehalfMap(String usersCredential) {
        String[] credAndRealm = usersCredential.split("@");
        String[] cred = credAndRealm[0].split(":");
        if (credAndRealm.length != 2 || cred.length != 2) {
            logger.warn("Could not parse usersCredential: {}", usersCredential);
            return;
        }
        String realm = credAndRealm[1];
        String login = cred[0];
        String password = cred[1];
        if (StringUtils.isBlank(realm) || StringUtils.isBlank(login) || StringUtils.isBlank(password)) {
            logger.warn("Some login:password@realm is empty in usersCredential: {}", usersCredential);
            return;
        }
        addRunOnBehalfOfUsers(login.trim(), password.trim(), realm.trim());
    }

    public boolean isAnonymousAllowed() {
        return anonymousAllowed;
    }

    public void setAnonymousAllowed(boolean anonymousAllowed) {
        this.anonymousAllowed = anonymousAllowed;
    }

    public boolean isSkipRefererCheck() {
        return skipRefererCheck;
    }

    public void setSkipRefererCheck(boolean skipRefererCheck) {
        this.skipRefererCheck = skipRefererCheck;
    }

    @Override
    public String toString() {
        return "OidcConfiguration{" +
                "identityProviderHost='" + identityProviderHost + '\'' +
                ", authorizationEndpoint='" + authorizationEndpoint + '\'' +
                ", logoutEndpoint='" + logoutEndpoint + '\'' +
                ", tokenEndpoint='" + tokenEndpoint + '\'' +
                ", clientId='" + clientId + '\'' +
                ", clientSecret='" + StringUtils.getMaskedString(clientSecret) + '\'' +
                ", username='" + username + '\'' +
                ", scope='" + scope + '\'' +
                ", checkIsActive=" + checkIsActive +
                ", checkTokenType=" + checkTokenType +
                ", useReferAsRedirectUri=" + useReferAsRedirectUri +
                ", defaultRealm='" + defaultRealm + '\'' +
                ", excludeValidationRealm='" + excludeValidationRealm + '\'' +
                ", tokenShouldBeRefreshed=" + tokenShouldBeRefreshed +
                ", securityInterceptorEnable=" + securityInterceptorEnable +
                ", urlResolver='" + urlResolver.toString()+ '\'' +
                ", filterApplyUrlPattern=" + interceptorUrlResolver.toString()+
                ", jwtBearerFilterEnable=" + jwtBearerFilterEnable  + '\'' +
                ", jwtBearerTokenRequired=" + jwtBearerTokenRequired  + '\'' +
                ", encodeRedirectUri=" + encodeRedirectUri  + '\'' +
                ", anonymousAllowed=" + anonymousAllowed  + '\'' +
                ", skipRefererCheck=" + skipRefererCheck  + '\'' +
                '}';
    }
}
