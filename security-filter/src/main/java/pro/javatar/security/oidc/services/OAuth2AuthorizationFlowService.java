package pro.javatar.security.oidc.services;

import pro.javatar.security.api.config.SecurityConfig;
import pro.javatar.security.jwt.adapter.AdapterRSATokenVerifier;
import pro.javatar.security.jwt.bean.representation.AccessToken;
import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.jwt.exception.TokenExpirationException;
import pro.javatar.security.jwt.exception.VerificationException;
import pro.javatar.security.oidc.client.OAuthClient;
import pro.javatar.security.oidc.exceptions.ExchangeTokenByCodeAuthenticationException;
import pro.javatar.security.oidc.exceptions.ObtainRefreshTokenException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

// TODO create bean
//@Service
public class OAuth2AuthorizationFlowService {
    private static final Logger logger = LoggerFactory.getLogger(OAuth2AuthorizationFlowService.class);

    private OAuthClient oAuthClient;

    private PublicKeyCacheService publicKeyCacheService;

    private SecurityConfig securityConfig;

    public OAuth2AuthorizationFlowService() {}

    public OAuth2AuthorizationFlowService(OAuthClient oAuthClient,
                                          PublicKeyCacheService publicKeyCacheService,
                                          SecurityConfig securityConfig) {
        this.oAuthClient = oAuthClient;
        this.publicKeyCacheService = publicKeyCacheService;
        this.securityConfig = securityConfig;
    }

    public TokenDetails getTokenDetailsByCode(String code, String redirectUrl)
            throws ExchangeTokenByCodeAuthenticationException {
        return oAuthClient.obtainTokenDetailsByAuthorizationCode(code, redirectUrl);
    }

    public TokenDetails getTokenByRefreshToken(String refreshToken) throws ObtainRefreshTokenException {
        return oAuthClient.obtainTokenDetailsByRefreshToken(refreshToken);
    }

    public TokenDetails obtainTokenByApplicationCredentials() {
        return oAuthClient.obtainTokenDetailsByApplicationCredentials();
    }

    public TokenDetails obtainTokenByRunOnBehalfOfUserCredentials(String user, String realm) {
        return oAuthClient.obtainTokenDetailsByRunOnBehalfOfUserCredentials(user, realm);
    }

    public TokenDetails obtainTokenDetailsByApplicationCredentials(String user, String password, String realm) {
        return oAuthClient.obtainTokenDetailsByApplicationCredentials(user, password, realm);
    }

    public AccessToken parseAccessToken(String accessToken, String realm) throws VerificationException,
            TokenExpirationException {
        logger.debug("Token realm is {}", realm);
        String publicKeyByRealm = publicKeyCacheService.getPublicKeyByRealm(realm);
        logger.debug("Public key [{}] was retrieved by realm={}", publicKeyByRealm, realm);
        try {
            return getAccessToken(accessToken, realm, publicKeyByRealm);
        } catch (Exception e) { // TODO catch different exceptions
            logger.trace("The first attempt to get access token is invalid. Trying again with refreshed public key." , e);
            String publicKey = publicKeyCacheService.refreshPublicKey(realm);
            return getAccessToken(accessToken, realm, publicKey);
        }
    }

    private AccessToken getAccessToken(String accessToken, String realm, String publicKeyByRealm)
            throws TokenExpirationException, VerificationException {
        return AdapterRSATokenVerifier.verifyToken(
                publicKeyByRealm,
                accessToken,
                realm,
                securityConfig.tokenValidation().checkTokenIsActive(),
                securityConfig.tokenValidation().checkTokenType());
    }

    @Autowired
    public void setoAuthClient(OAuthClient oAuthClient) {
        this.oAuthClient = oAuthClient;
    }

    @Autowired
    public void setPublicKeyCacheService(PublicKeyCacheService publicKeyCacheService) {
        this.publicKeyCacheService = publicKeyCacheService;
    }
}
