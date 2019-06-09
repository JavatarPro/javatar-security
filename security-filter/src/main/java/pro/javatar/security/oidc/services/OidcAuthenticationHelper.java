package pro.javatar.security.oidc.services;

import pro.javatar.security.api.config.SecurityConfig;
import pro.javatar.security.jwt.adapter.AdapterRSATokenVerifier;
import pro.javatar.security.oidc.client.OAuthClient;
import pro.javatar.security.oidc.model.OAuth2Constants;
import pro.javatar.security.jwt.TokenVerifier;
import pro.javatar.security.jwt.bean.representation.AccessToken;
import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.jwt.exception.TokenExpirationException;
import pro.javatar.security.jwt.exception.VerificationException;
import pro.javatar.security.oidc.SecurityConstants;
import pro.javatar.security.oidc.exceptions.BearerJwtTokenNotFoundAuthenticationException;
import pro.javatar.security.oidc.exceptions.MaliciousBearerJwtTokenAuthenticationException;
import pro.javatar.security.oidc.exceptions.ObtainRefreshTokenException;
import pro.javatar.security.oidc.exceptions.RealmInJwtTokenNotFoundAuthenticationException;
import pro.javatar.security.oidc.exceptions.RefreshTokenObsoleteAuthenticationException;
import pro.javatar.security.oidc.services.api.RealmService;
import pro.javatar.security.oidc.utils.SecurityContextUtils;
import pro.javatar.security.oidc.utils.StringUtils;

import org.apache.http.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.text.MessageFormat;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;

@Service
public class OidcAuthenticationHelper {

    private static final Logger logger = LoggerFactory.getLogger(OidcAuthenticationHelper.class);

    public static final String AUTH_HEADER_VALUE_PREFIX = "Bearer ";

    private OidcConfiguration oidcConfiguration;

    private OAuthClient oAuthClient;

    private SecurityConfig config;

    private RealmService realmService;

    public OidcAuthenticationHelper() {}

    public OidcAuthenticationHelper(OidcConfiguration oidcConfiguration,
                                    OAuthClient oAuthClient,
                                    SecurityConfig config,
                                    RealmService realmService) {
        this.oidcConfiguration = oidcConfiguration;
        this.oAuthClient = oAuthClient;
        this.config = config;
        this.realmService = realmService;
    }

    /**
     * Get the bearer token from the HTTP request.
     * The token is in HTTP session firstly or in the HTTP request "Authorization" header in the form of: "Bearer [token]"
     */
    public String getBearerToken(HttpServletRequest request) {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        return obtainCleanBearerToken(authHeader);
    }

    public String getBearerToken(HttpServletResponse response) {
        String authorizationHeader = response.getHeader(HttpHeaders.AUTHORIZATION);
        return obtainCleanBearerToken(authorizationHeader);
    }

    public TokenDetails getTokenDetails(HttpServletResponse response) {
        return generateTokenDetails(getBearerToken(response), getRefreshToken(response));
    }

    public String getRefreshToken(HttpServletResponse response) {
        return response.getHeader(SecurityConstants.REFRESH_TOKEN_HEADER);
    }

    public String getRefreshToken(HttpServletRequest request) {
        return request.getHeader(SecurityConstants.REFRESH_TOKEN_HEADER);
    }

    public String createRedirectUrl(String redirectUrlTemplate, HttpServletRequest request)
            throws UnsupportedEncodingException {
        String requestUrl = request.getRequestURL().toString();
        return MessageFormat.format(redirectUrlTemplate, URLEncoder.encode(requestUrl, "UTF-8"));
    }

    public void setRealmForCurrentRequest(String realm) {
        realmService.setRealmForCurrentRequest(realm);
    }

    public String getRealmForCurrentRequest() {
        return realmService.getRealmForCurrentRequest();
    }

    public String getRealmForCurrentRequest(HttpServletResponse response) {
        return realmService.getRealmForCurrentRequest(response);
    }

    public void validateRealm(TokenDetails tokenDetails) {
        realmService.validateRealm(tokenDetails);
    }

    public void removeRealmFromCurrentRequest() {
        realmService.removeRealmFromCurrentRequest();
    }

    public boolean shouldApplyUrl(HttpRequest request) {
        return oidcConfiguration.getUrlResolver().apply(request);
    }

    public boolean shouldSkip(HttpRequest request) {
        return !shouldApplyUrl(request);
    }

    public void authenticateCurrentThread(String accessToken, String refreshToken) {
        TokenDetails tokenDetails = generateTokenDetails(accessToken, accessToken);
        authenticateCurrentThread(tokenDetails);
    }

    public void authenticateCurrentThread(TokenDetails tokenDetails) {
        logger.info("Start authenticate current thread");
        AccessToken accessToken = parseAccessToken(tokenDetails);
        AccessToken.Access access =
                accessToken.getResourceAccess().get(oidcConfiguration.getClientId());
        Collection<GrantedAuthority> authorities = retrieveAuthorities(access);
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(accessToken.getPreferredUsername(), tokenDetails, authorities);

        SecurityContextUtils.setAuthentication(authenticationToken);
        logger.info("Finish authenticate current thread");
    }

    // TODO remove to not depend on oAuthClient
    @Deprecated
    public AccessToken parseAccessToken(TokenDetails tokenDetails) {
        String accessToken = getAccessToken(tokenDetails);
        String realm = getRealmFromToken(accessToken);
        try {
            return oAuthClient.parseAccessToken(accessToken, realm);
        } catch (TokenExpirationException e) {
            logger.debug("Access token is not active: {}, realm: {}", accessToken, realm, e);
            return changeRefreshToken(tokenDetails, accessToken, realm);
        } catch (VerificationException e) {
            logger.error("Malicious token: {}, realm: {}", accessToken, realm, e);
            throw new MaliciousBearerJwtTokenAuthenticationException();
        }
    }

    public String removeCodeFromUrl(String url, String code) {
        return url.replaceFirst("&?code=" + code, "");
    }

    public String removeCodeFromUrl(HttpServletRequest request) {
        String code = request.getParameter(OAuth2Constants.CODE);
        String url = request.getRequestURL().toString();
        String cleanUrl = removeCodeFromUrl(url, code);
        logger.info("Code was removed from request. Clean url looks like {}", cleanUrl);
        return cleanUrl;
    }

    public boolean isTokenExpiredOrShouldBeRefreshed(TokenDetails tokenDetails) {
        if (tokenDetails.getAccessTokenExpiration() == null) return true;
        LocalDateTime refreshDate =
                LocalDateTime.now().plusSeconds(oidcConfiguration.getTokenShouldBeRefreshed());
        return tokenDetails.getAccessTokenExpiration().isBefore(refreshDate);
    }

    // TODO remove to not depend on oAuthClient
    // use instead pro.javatar.security.oidc.client.OAuthClient.generateTokenDetails
    @Deprecated
    public TokenDetails generateTokenDetails(String accessToken, String refreshToken) {
        if (StringUtils.isBlank(accessToken))
            return new TokenDetails();
        AccessToken token;
        try {
            token = oAuthClient.parseAccessToken(accessToken, getRealmFromToken(accessToken));
        } catch (VerificationException e) {
            logger.error("Malicious token: {}, realm: {}", accessToken, TokenVerifier.getRealm(accessToken), e);
            throw new MaliciousBearerJwtTokenAuthenticationException();
        } catch (TokenExpirationException e) {
            logger.debug("Access token is expired trying to refresh one...", e);
            TokenDetails tokenDetails;
            String realmFromToken = getRealmFromToken(accessToken);
            try {
                // TODO
                tokenDetails = oAuthClient.obtainTokenDetailsByRefreshToken(refreshToken);
                token = oAuthClient.parseAccessToken(tokenDetails.getAccessToken(), realmFromToken);
                return createTokenDetails(tokenDetails.getAccessToken(), tokenDetails.getRefreshToken(),
                        token.getExpiration());
            } catch (Exception e1) {
                logger.error("Refresh token is spoiled: {}, realm: {}", StringUtils.getMaskedString(refreshToken),
                        realmFromToken, e1);
                throw new RefreshTokenObsoleteAuthenticationException();
            }
        }
        return createTokenDetails(accessToken, refreshToken, token.getExpiration());
    }

    private TokenDetails createTokenDetails(String accessToken, String refreshToken, int expiration){
        LocalDateTime accessTokenExpiration =
                LocalDateTime.ofInstant(Instant.ofEpochSecond(expiration), ZoneId.systemDefault());
        return new TokenDetails(accessToken, refreshToken, accessTokenExpiration);
    }

    public void safeCleanupSecurityContext(Class clazz) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getCredentials() instanceof TokenDetails)) {
            return;
        }
        TokenDetails tokenDetails = (TokenDetails) authentication.getCredentials();
        if (tokenDetails != null && tokenDetails.getCredentialsProvider() == clazz) {
            SecurityContextHolder.clearContext();
        }
    }

    private AccessToken getAccessToken(String accessToken, String realm, String publicKeyByRealm)
            throws TokenExpirationException, VerificationException {
        return AdapterRSATokenVerifier.verifyToken(
                publicKeyByRealm,
                accessToken,
                realm,
                config.tokenValidation().checkTokenIsActive(),
                config.tokenValidation().checkTokenType());
    }

    // TODO refactor to not depend on oAuthClient
    @Deprecated
    private AccessToken changeRefreshToken(TokenDetails tokenDetails, String accessToken, String realm) {
        try {
            TokenDetails refreshedTokenDetails =
                    oAuthClient.obtainTokenDetailsByRefreshToken(tokenDetails.getRefreshToken());
            return oAuthClient.parseAccessToken(refreshedTokenDetails.getAccessToken(), realm);
        } catch (VerificationException | TokenExpirationException e) {
            logger.error("Malicious token: {}, realm: {}", accessToken, realm, e);
            throw new MaliciousBearerJwtTokenAuthenticationException();
        } catch (Exception ex) {
            logger.error("Error during obtaining access token by refresh one.", ex);
            throw new ObtainRefreshTokenException();
        }
    }

    private String obtainCleanBearerToken(String bearerToken) {
        if (StringUtils.isBlank(bearerToken)) {
            return null;
        }
        return bearerToken.startsWith(AUTH_HEADER_VALUE_PREFIX) ?
                bearerToken.substring(AUTH_HEADER_VALUE_PREFIX.length()) : bearerToken;

    }

    // use instead pro.javatar.security.oidc.services.api.RealmService.getRealmFromToken
    @Deprecated
    private String getRealmFromToken(String accessToken) {
        String realm = TokenVerifier.getRealm(accessToken);
        if (StringUtils.isBlank(realm)) {
            logger.error("Unable to obtain realm from Access token.");
            throw new RealmInJwtTokenNotFoundAuthenticationException();
        }
        return realm;
    }

    private String getAccessToken(TokenDetails tokenDetails) {
        String accessToken = tokenDetails.getAccessToken();
        if (StringUtils.isBlank(accessToken)) {
            logger.error("Token is empty.");
            throw new BearerJwtTokenNotFoundAuthenticationException();
        }
        return accessToken;
    }

    private Collection<GrantedAuthority> retrieveAuthorities(AccessToken.Access access) {
        if (access == null) {
            return Collections.emptyList();
        }
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        Set<String> clientRoles = access.getRoles();
        for (String role : clientRoles) {
            authorities.add(new SimpleGrantedAuthority(role));
        }
        return authorities;
    }

    @Autowired
    public void setOidcConfiguration(OidcConfiguration oidcConfiguration) {
        this.oidcConfiguration = oidcConfiguration;
    }

    @Autowired
    public void setOAuthClient(OAuthClient oAuthClient) {
        this.oAuthClient = oAuthClient;
    }

    @Autowired
    public void setConfig(SecurityConfig config) {
        this.config = config;
    }

    @Autowired
    public void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }
}
