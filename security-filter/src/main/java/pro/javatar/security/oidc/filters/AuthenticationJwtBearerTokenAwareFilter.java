package pro.javatar.security.oidc.filters;

import pro.javatar.security.api.config.SecurityConfig;
import pro.javatar.security.oidc.client.OAuthClient;
import pro.javatar.security.oidc.model.OAuth2Constants;
import pro.javatar.security.jwt.TokenVerifier;
import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.SecurityConstants;
import pro.javatar.security.oidc.exceptions.BearerJwtTokenNotFoundAuthenticationException;
import pro.javatar.security.oidc.exceptions.ExchangeTokenByCodeAuthenticationException;
import pro.javatar.security.oidc.services.OidcAuthenticationHelper;
import pro.javatar.security.oidc.utils.StringUtils;

import org.apache.http.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpRequest;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * This filter authenticate and authorize user by bearer token or by authorization code.
 * Please see rfc6749, rfc6750 for more details.
 */
@Component
public class AuthenticationJwtBearerTokenAwareFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationJwtBearerTokenAwareFilter.class);

    public static final String DIGEST_AUTHORIZATION_HEADER_SCHEMA = "Digest";

    public static final String BASIC_AUTHORIZATION_HEADER_SCHEMA = "Basic";

    private SecurityConfig config;

    // TODO (bzo) ask configuration about is filter enable/disable
    private AuthorizationStubFilter authorizationStubFilter;

    private OAuthClient oAuthClient;

    private OidcAuthenticationHelper oidcHelper;

    @Override
    public void init(FilterConfig filterConfig) {
        logger.info("AuthenticationJwtBearerTokenAwareFilter initialized");
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
                         FilterChain filterChain) throws IOException, ServletException {
        // TODO remove stub
        boolean stubFilterEnable = authorizationStubFilter.isFilterEnable();
        if (!config.securityFilter().isJwtBearerFilterEnable() || stubFilterEnable) {
            logger.debug("{} is disabled. Dev mode is {}.", getClass().getCanonicalName(),
                    stubFilterEnable ? "on" : "off");
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        if (shouldSkip(request)) {
            logger.debug("Filter was skipped by filter condition.");
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        if (isOtherAuthenticationAllowed()) {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null && authentication.isAuthenticated()) {
                logger.debug("authentication was obtained by other method");
                filterChain.doFilter(servletRequest, servletResponse);
                return;
            }
        }

        try {
            authenticate(request, response);
            filterChain.doFilter(servletRequest, servletResponse);
        } finally {
            oidcHelper.safeCleanupSecurityContext(AuthenticationJwtBearerTokenAwareFilter.class);
        }
    }

    @Override
    public void destroy() {
        logger.info("AuthenticationJwtBearerTokenAwareFilter destroyed");
    }

    boolean shouldSkip(ServletRequest request) {
        return shouldSkip(new ServletServerHttpRequest((HttpServletRequest) request));
    }

    /**
     * If necessary, the method can be redefined
     *
     * @param request
     * @return <code>true</code> filter is ignored
     */
    boolean shouldSkip(HttpRequest request) {
        return oidcHelper.shouldSkip(request);
    }

    void authenticate(HttpServletRequest request, HttpServletResponse response) {
        TokenDetails tokenDetails = obtainJwtBearerToken(request);
        if (tokenDetails == null && config.securityFilter().isAnonymousAllowed()) {
            logger.debug("skipping authentication bearer token not found but anonymous is allowed");
            return;
        }
        if (tokenDetails == null) {
            logger.warn("Did not obtain token from request.");
            return;
        }
        tokenDetails.setCredentialsProvider(AuthenticationJwtBearerTokenAwareFilter.class);
        String tokenRealm = TokenVerifier.getRealm(tokenDetails.getAccessToken());
        tokenDetails.setRealm(tokenRealm);
        oidcHelper.validateRealm(tokenDetails);
        oidcHelper.authenticateCurrentThread(tokenDetails);
        setupAuthorizationHeader(response, tokenDetails);
    }


    void setupAuthorizationHeader(HttpServletResponse response, TokenDetails tokenDetails) {
        logger.debug("Setup authorization/refresh tokens");
        response.addHeader(HttpHeaders.AUTHORIZATION,
                OidcAuthenticationHelper.AUTH_HEADER_VALUE_PREFIX + tokenDetails.getAccessToken());
        String refreshToken = tokenDetails.getRefreshToken();
        response.addHeader(SecurityConstants.REFRESH_TOKEN_HEADER, StringUtils.isNotBlank(refreshToken) ?
                refreshToken :
                "");
    }

    TokenDetails obtainJwtBearerToken(HttpServletRequest request) throws BearerJwtTokenNotFoundAuthenticationException {
        if (isHeaderTokenPresent(request)) {
            return oidcHelper.generateTokenDetails(oidcHelper.getBearerToken(request), oidcHelper.getRefreshToken(request));
        }

        if (isAuthorizationCodePresent(request) &&
                isAuthorizationCodePassedByIdentityProvider(request)) {
            return exchangeAuthorizationCodeForBearerToken(request);
        }
        if (config.securityFilter().isAnonymousAllowed()) {
            return null;
        } else {
            throw new BearerJwtTokenNotFoundAuthenticationException();
        }
    }

    TokenDetails exchangeAuthorizationCodeForBearerToken(HttpServletRequest request)
            throws ExchangeTokenByCodeAuthenticationException {
        String secureCode = request.getParameter(OAuth2Constants.CODE);
        try {
            String redirectUrl = request.getRequestURL().toString();
            String referer = request.getHeader(SecurityConstants.REFERER_HEADER);
            if (config.redirect().isUseReferAsRedirectUri() && StringUtils.isNotBlank(referer)) {
                redirectUrl = referer;
            }
            redirectUrl = oidcHelper.removeCodeFromUrl(redirectUrl, secureCode);
            return oAuthClient.obtainTokenDetailsByAuthorizationCode(secureCode, redirectUrl);
        } catch (Exception e) {
            logger.error("Error during obtaining access token by authorization code:", e);
            ExchangeTokenByCodeAuthenticationException exchangeTokenByCodeAuthenticationException =
                    new ExchangeTokenByCodeAuthenticationException();
            exchangeTokenByCodeAuthenticationException.setDevMessage(e.getMessage());
            throw exchangeTokenByCodeAuthenticationException;
        }
    }

    boolean isAuthorizationCodePresent(HttpServletRequest request) {
        return StringUtils.isNotBlank(request.getParameter(OAuth2Constants.CODE));
    }

    boolean isHeaderTokenPresent(HttpServletRequest request) {
        String token = oidcHelper.getBearerToken(request);
        return StringUtils.isNotBlank(token) && !token.startsWith(DIGEST_AUTHORIZATION_HEADER_SCHEMA)
                && !token.startsWith(BASIC_AUTHORIZATION_HEADER_SCHEMA);
    }

    boolean isOtherAuthenticationAllowed() {
        return config.securityFilter().isJwtBearerTokenOtherAuthenticationAllowed();
    }

    private boolean isAuthorizationCodePassedByIdentityProvider(HttpServletRequest request) {
        String referrer = request.getHeader(SecurityConstants.REFERER_HEADER);
        if (StringUtils.isBlank(config.identityProvider().url())) {
            logger.warn("IdentityProviderHost not set");
            return true;
        }
        if(config.isSkipRefererCheck()){
            logger.debug("Skipping referer check.");
            return true;
        }
        boolean refererPresent = StringUtils.isNotBlank(referrer);
        logger.info("Referer is " + (refererPresent ? "present" : " NOT present" + " in headers."));
        return refererPresent;
    }

    @Autowired
    public void setoAuthClient(OAuthClient oAuthClient) {
        this.oAuthClient = oAuthClient;
    }

    @Autowired
    public void setOidcHelper(OidcAuthenticationHelper oidcHelper) {
        this.oidcHelper = oidcHelper;
    }

    @Autowired
    public void setAuthorizationStubFilter(AuthorizationStubFilter authorizationStubFilter) {
        this.authorizationStubFilter = authorizationStubFilter;
    }

    @Autowired
    public void setConfig(SecurityConfig config) {
        this.config = config;
    }
}

