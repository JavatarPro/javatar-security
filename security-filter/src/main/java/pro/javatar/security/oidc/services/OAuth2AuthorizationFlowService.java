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

// TODO remove
//@Service
public class OAuth2AuthorizationFlowService {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2AuthorizationFlowService.class);

    private OAuthClient oAuthClient;

    private SecurityConfig securityConfig;

    public OAuth2AuthorizationFlowService() {}

    public OAuth2AuthorizationFlowService(OAuthClient oAuthClient,
                                          SecurityConfig securityConfig) {
        this.oAuthClient = oAuthClient;
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

    @Autowired
    public void setoAuthClient(OAuthClient oAuthClient) {
        this.oAuthClient = oAuthClient;
    }

}
