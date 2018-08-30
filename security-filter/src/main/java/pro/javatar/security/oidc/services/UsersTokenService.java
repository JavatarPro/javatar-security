package pro.javatar.security.oidc.services;

import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.exceptions.ObtainRefreshTokenException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class UsersTokenService {

    private static final Logger logger = LoggerFactory.getLogger(UsersTokenService.class);

    private OidcAuthenticationHelper oidcAuthenticationHelper;

    private OAuth2AuthorizationFlowService oAuth2AuthorizationFlowService;

    @Autowired
    public UsersTokenService(OidcAuthenticationHelper oidcAuthenticationHelper,
                             OAuth2AuthorizationFlowService oAuth2AuthorizationFlowService) {
        this.oidcAuthenticationHelper = oidcAuthenticationHelper;
        this.oAuth2AuthorizationFlowService = oAuth2AuthorizationFlowService;
    }

    public TokenDetails retrieveUsersTokenDetails() {
        TokenDetails tokenDetails = retrieveUsersTokenDetailsFromSecurityContext();
        if (tokenDetails.isNotEmpty() && oidcAuthenticationHelper.isTokenExpiredOrShouldBeRefreshed(tokenDetails)) {
            return retrieveUpdatedUsersTokenDetails(tokenDetails);
        }
        return tokenDetails;
    }

    TokenDetails retrieveUsersTokenDetailsFromSecurityContext() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getCredentials() instanceof TokenDetails) {
            return  (TokenDetails) authentication.getCredentials();
        }
        logger.debug("could not retrieve user's token details from security context.");
        return new TokenDetails();
    }

    TokenDetails retrieveUpdatedUsersTokenDetails(TokenDetails tokenDetails) {
        try {
            String refreshToken = tokenDetails.getRefreshToken();
            TokenDetails updatedTokenDetails = oAuth2AuthorizationFlowService.getTokenByRefreshToken(refreshToken);
            // we need to update with new token details current thread,
            // because requester needs it in response to update tokens on ui
            oidcAuthenticationHelper.authenticateCurrentThread(updatedTokenDetails);
            return updatedTokenDetails;
        } catch (ObtainRefreshTokenException e) {
            logger.error("could not obtain tokenDetails using refresh token, old one will be returned instead", e);
            return tokenDetails;
        }
    }

}
