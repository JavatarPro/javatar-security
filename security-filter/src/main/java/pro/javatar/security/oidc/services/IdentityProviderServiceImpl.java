package pro.javatar.security.oidc.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.exceptions.ObtainRefreshTokenException;

@Service
public class IdentityProviderServiceImpl implements IdentityProviderService {

    private static final Logger logger = LoggerFactory.getLogger(IdentityProviderServiceImpl.class);

    private OidcAuthenticationHelper oidcHelper;

    private OAuth2AuthorizationFlowService auth2AuthorizationFlowService;

    @Autowired
    public IdentityProviderServiceImpl(OidcAuthenticationHelper oidcHelper,
                                       OAuth2AuthorizationFlowService auth2AuthorizationFlowService) {
        this.oidcHelper = oidcHelper;
        this.auth2AuthorizationFlowService = auth2AuthorizationFlowService;
    }

    @Override
    public TokenDetails getNotExpiredToken(String accessToken, String refreshToken) {
        TokenDetails token = oidcHelper.generateTokenDetails(accessToken, refreshToken);

        if (oidcHelper.isTokenExpiredOrShouldBeRefreshed(token)) {
            logger.info("try refresh token pair, because access token expires or close enough to expiration");
            try {
                token = auth2AuthorizationFlowService.getTokenByRefreshToken(refreshToken);
            } catch (ObtainRefreshTokenException e) {
                logger.warn("Could not obtain new token pair, exception was while refreshing token. " +
                        "Old token will be returned", e);
            }
        } else {
            logger.debug("access token is good, do not need refresh it");
        }
        return token;
    }

}
