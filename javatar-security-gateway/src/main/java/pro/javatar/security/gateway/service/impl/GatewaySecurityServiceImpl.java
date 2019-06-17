package pro.javatar.security.gateway.service.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import pro.javatar.secret.storage.api.SecretStorageService;
import pro.javatar.secret.storage.api.exception.DeleteFailedSecretStorageException;
import pro.javatar.secret.storage.api.exception.PersistenceSecretStorageException;
import pro.javatar.secret.storage.api.exception.TokenNotFoundSecretStorageException;
import pro.javatar.secret.storage.api.model.SecretTokenDetails;
import pro.javatar.security.api.AuthService;
import pro.javatar.security.api.config.SecurityConfig;
import pro.javatar.security.gateway.exception.LoginException;
import pro.javatar.security.gateway.model.GatewayResponse;
import pro.javatar.security.gateway.model.HeaderMapRequestWrapper;
import pro.javatar.security.gateway.service.api.GatewaySecurityService;
import pro.javatar.security.api.exception.IssueTokensException;
import pro.javatar.security.api.model.AuthRequestBO;
import pro.javatar.security.api.model.TokenInfoBO;
import pro.javatar.security.gateway.service.impl.util.CookieUtil;
import pro.javatar.security.oidc.services.OidcAuthenticationHelper;
import pro.javatar.security.oidc.utils.StringUtils;

import javax.servlet.ServletRequest;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;
import java.util.UUID;

import static org.apache.http.HttpHeaders.AUTHORIZATION;
import static pro.javatar.security.oidc.SecurityConstants.REALM_HEADER;
import static pro.javatar.security.oidc.SecurityConstants.REFRESH_TOKEN_HEADER;

/**
 * @author Borys Zora
 * @version 2019-06-01
 */
@Service
public class GatewaySecurityServiceImpl implements GatewaySecurityService {

    public static final String TOKEN_ID = "tokenID";

    private static final Logger logger = LoggerFactory.getLogger(GatewaySecurityServiceImpl.class);

    private AuthService authService;

    private SecretStorageService secretService;

    private SecurityConfig config;

    private OidcAuthenticationHelper oidcHelper;

    @Autowired
    public GatewaySecurityServiceImpl(AuthService authService,
                                      SecretStorageService secretService,
                                      SecurityConfig config,
                                      OidcAuthenticationHelper oidcHelper) {
        this.authService = authService;
        this.secretService = secretService;
        this.config = config;
        this.oidcHelper = oidcHelper;
    }

    @Override
    public String login(AuthRequestBO authRequest,
                        HttpServletRequest request,
                        HttpServletResponse response) throws LoginException {
        try {
            populateRealmInAuthRequestIfMissing(authRequest);
            TokenInfoBO authToken = authService.issueTokens(authRequest);

            String realm = authRequest.getRealm();
            String ipAddress = request.getRemoteAddr();
            SecretTokenDetails secretToken = getSecretTokenDetails(realm, ipAddress, authToken);

            String correlationId = UUID.randomUUID().toString();
            secretService.put(correlationId, secretToken);

            CookieUtil.createSecureCookie(response, TOKEN_ID, correlationId);
            return correlationId;
        } catch (IssueTokensException | PersistenceSecretStorageException e) {
            logger.error(e.getMessage(), e);
            throw new LoginException(e.getMessage());
        }
    }

    // TODO find out how to extract ip address and other info precisely
    @Override
    public void exchangeToken(GatewayResponse response) {
        Map<String, Object> gatewayHeaders = response.getResponseGatewayHeaders();

        // TODO validate previous token as well
        if (!gatewayHeaders.containsKey(HttpHeaders.AUTHORIZATION)) {
            logger.debug("Authorization header is not found, tokenID is not exchanged");
            return;
        }

        SecretTokenDetails secretToken = new SecretTokenDetails();
        // TODO use only access & refresh tokens all other info we can retrieve from previous token,
        //  that should be provided
        // secretToken.setAccessToken((String) gatewayHeaders.get(HttpHeaders.AUTHORIZATION));
        // secretToken.setRefreshToken((String) gatewayHeaders.get(SecurityConstants.REFRESH_TOKEN_HEADER));
        // secretToken.setRealm((String) gatewayHeaders.get(SecurityConstants.REALM_HEADER))
        String correlationId = UUID.randomUUID().toString();
        try {
            secretService.put(correlationId, secretToken);
            CookieUtil.createSecureCookie(response.getResponse(), TOKEN_ID, correlationId);
        } catch (PersistenceSecretStorageException e) {
            logger.warn(e.getMessage(), e);
        }
    }

    @Override
    public void appendSecurityHeaders(HeaderMapRequestWrapper requestWrapper) {
        String secretKey = CookieUtil.getCookie(TOKEN_ID, requestWrapper.getCookies());

        if (StringUtils.isBlank(secretKey)) {
            logger.debug("authorizationKey is blank, skip retrieve from secret storage");
            return;
        }

        SecretTokenDetails secretTokenDetails = null;
        try {
            secretTokenDetails = secretService.get(secretKey);
            // TODO if close to expiration exchange refresh token
        } catch (TokenNotFoundSecretStorageException e) {
            logger.error(e.getMessage(), e);
            // TODO throw exception
        }

        if (secretTokenDetails == null || secretTokenDetails.isEmpty()) {
            logger.info("Token details is empty");
            // TODO throw exception
            return;
        }

        requestWrapper.addHeader(AUTHORIZATION, secretTokenDetails.getAccessToken());
        requestWrapper.addHeader(REFRESH_TOKEN_HEADER, secretTokenDetails.getRefreshToken());
        requestWrapper.addHeader(REALM_HEADER, secretTokenDetails.getRealm());
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        String secretKey = CookieUtil.getCookie(TOKEN_ID, cookies);
        // TODO remove parent vault key, rotate keys more frequently
        try {
            secretService.delete(secretKey);
        } catch (DeleteFailedSecretStorageException e) {
            logger.error(e.getMessage(), e);
        }
        CookieUtil.removeCookie(response, TOKEN_ID);
    }

    @Override
    public boolean shouldApplyUrl(ServletRequest request) {
        HttpServletRequest req = (HttpServletRequest) request;
        String method = req.getMethod();
        String path = req.getRequestURI();
        return oidcHelper.shouldApplyUrl(method, path);
    }

    private SecretTokenDetails getSecretTokenDetails(String realm,
                                                     String ipAddress,
                                                     TokenInfoBO authToken) {
        SecretTokenDetails secretToken = new SecretTokenDetails();
        secretToken.setAccessToken(authToken.getAccessToken());
        secretToken.setRefreshToken(authToken.getRefreshToken());
        secretToken.setRealm(realm);
        String sessionToken = UUID.randomUUID().toString();
        secretToken.setSessionId(sessionToken);
        secretToken.setIpAddress(ipAddress);
        return secretToken;
    }

    private void populateRealmInAuthRequestIfMissing(AuthRequestBO authRequest) {
        if (authRequest.getRealm() == null) {
            authRequest.setRealm(config.identityProvider().realm());
        }
    }
}
