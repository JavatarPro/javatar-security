package pro.javatar.security.gateway.service.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import pro.javatar.secret.storage.api.SecretStorageService;
import pro.javatar.secret.storage.api.exception.DeleteFailedSecretStorageException;
import pro.javatar.secret.storage.api.exception.PersistenceSecretStorageException;
import pro.javatar.secret.storage.api.exception.TokenNotFoundSecretStorageException;
import pro.javatar.secret.storage.api.model.SecretTokenDetails;
import pro.javatar.security.api.AuthService;
import pro.javatar.security.api.SecurityService;
import pro.javatar.security.api.config.SecurityConfig;
import pro.javatar.security.gateway.exception.LoginException;
import pro.javatar.security.gateway.model.HeaderMapRequestWrapper;
import pro.javatar.security.gateway.service.api.CookieService;
import pro.javatar.security.gateway.service.api.GatewaySecurityService;
import pro.javatar.security.api.exception.IssueTokensException;
import pro.javatar.security.api.model.AuthRequestBO;
import pro.javatar.security.api.model.TokenInfoBO;
import pro.javatar.security.oidc.exceptions.ObtainRefreshTokenException;
import pro.javatar.security.oidc.services.OidcAuthenticationHelper;
import pro.javatar.security.oidc.utils.StringUtils;

import javax.servlet.ServletRequest;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.*;

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

    private SecurityService securityService;

    private CookieService cookieService;

    private Set<String> excludedHeaders = new HashSet<>();

    @Autowired
    public GatewaySecurityServiceImpl(AuthService authService,
                                      SecretStorageService secretService,
                                      SecurityConfig config,
                                      OidcAuthenticationHelper oidcHelper,
                                      CookieService cookieService,
                                      SecurityService securityService) {
        this.authService = authService;
        this.secretService = secretService;
        this.config = config;
        this.oidcHelper = oidcHelper;
        this.securityService = securityService;
        this.cookieService = cookieService;
        prepareExcludedHeaders();
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

            return prepareSecretCookies(response, authToken, realm, ipAddress);
        } catch (IssueTokensException | PersistenceSecretStorageException e) {
            logger.error(e.getMessage(), e);
            throw new LoginException(e.getMessage());
        }
    }

    @Override
    public void appendSecurityHeaders(HeaderMapRequestWrapper requestWrapper) {
        SecretTokenDetails secretTokenDetails = getSecretTokenDetails(requestWrapper);

        // TODO if close to expiration exchange refresh token
        //  validate token
        if (secretTokenDetails == null || secretTokenDetails.isEmpty()) {
            logger.warn("Token details is empty. Security headers are not added for request: {}",
                    requestWrapper.getRequestURI());
            return;
        }

        requestWrapper.addHeader(AUTHORIZATION, secretTokenDetails.getAccessToken());
        requestWrapper.addHeader(REFRESH_TOKEN_HEADER, secretTokenDetails.getRefreshToken());
        requestWrapper.addHeader(REALM_HEADER, secretTokenDetails.getRealm());

        logger.debug("Security headers successfully added for request: {}", requestWrapper.getRequestURI());
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        String secretKey = cookieService.getCookie(TOKEN_ID, cookies);
        // TODO remove parent vault key, rotate keys more frequently
        try {
            secretService.delete(secretKey);
        } catch (DeleteFailedSecretStorageException e) {
            logger.error(e.getMessage(), e);
        }
        cookieService.removeCookie(response, TOKEN_ID);
    }

    @Override
    public boolean shouldApplyUrl(ServletRequest request) {
        HttpServletRequest req = (HttpServletRequest) request;
        String method = req.getMethod();
        String path = req.getRequestURI();
        return oidcHelper.shouldApplyUrl(method, path);
    }

    @Override
    public Set<String> excludedHeaders() {
        return excludedHeaders;
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

    private String prepareSecretCookies(HttpServletResponse response,
                                        TokenInfoBO authToken,
                                        String realm,
                                        String ipAddress) throws PersistenceSecretStorageException {
        SecretTokenDetails secretToken = getSecretTokenDetails(realm, ipAddress, authToken);

        String correlationId = UUID.randomUUID().toString();
        secretService.put(correlationId, secretToken);

        cookieService.createSecureCookie(response, TOKEN_ID, correlationId);
        return correlationId;
    }

    private SecretTokenDetails getSecretTokenDetails(HeaderMapRequestWrapper requestWrapper) {
        String secretKey = cookieService.getCookie(TOKEN_ID, requestWrapper.getCookies());

        if (StringUtils.isBlank(secretKey)) {
            logger.debug("authorizationKey is blank, skip retrieve from secret storage");
            return null;
        }

        try {
            return secretService.get(secretKey);
        } catch (TokenNotFoundSecretStorageException e) {
            logger.warn(e.getMessage(), e);
            return null;
        }
    }

    private void populateRealmInAuthRequestIfMissing(AuthRequestBO authRequest) {
        if (authRequest.getRealm() == null) {
            authRequest.setRealm(config.identityProvider().realm());
        }
    }

    private void prepareExcludedHeaders() {
        excludedHeaders.add(REFRESH_TOKEN_HEADER);
        excludedHeaders.add(REALM_HEADER);
        excludedHeaders.add(AUTHORIZATION);
    }

    // TODO find out how to extract ip address and other info precisely
    String exchangeToken(HttpServletRequest request,
                         HttpServletResponse response) {
        // TODO validate ip address of who is trying to refresh token
        String ipAddress = request.getRemoteAddr();
        try {
            // TODO Does not work, no headers at that point
            String refreshToken = oidcHelper.getRefreshToken(request);
            TokenInfoBO authToken = authService.reIssueTokens(refreshToken);

            String realm = securityService.getUser(authToken.getAccessToken()).getRealm();
            return prepareSecretCookies(response, authToken, realm, ipAddress);
        } catch (ObtainRefreshTokenException | PersistenceSecretStorageException e) {
            logger.error(e.getMessage(), e);
            throw new LoginException(e.getMessage());
        }

    }

}
