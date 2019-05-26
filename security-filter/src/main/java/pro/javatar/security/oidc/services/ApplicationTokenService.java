package pro.javatar.security.oidc.services;

import pro.javatar.security.oidc.client.OAuthClient;
import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.exceptions.ObtainRefreshTokenException;
import pro.javatar.security.oidc.model.UserKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class ApplicationTokenService {

    private static final Logger logger = LoggerFactory.getLogger(ApplicationTokenService.class);

    private OAuthClient oAuthClient;

    private OidcAuthenticationHelper oidcAuthenticationHelper;

    private OnBehalfOfUsernameHolder onBehalfOfUsernameHolder;

    private ApplicationTokenHolder applicationTokenHolder;

    private OidcConfiguration oidcConfiguration;

    @Autowired
    public ApplicationTokenService(OAuthClient oAuthClient,
                                   OidcAuthenticationHelper oidcAuthenticationHelper,
                                   OnBehalfOfUsernameHolder onBehalfOfUsernameHolder,
                                   ApplicationTokenHolder applicationTokenHolder,
                                   OidcConfiguration oidcConfiguration) {
        this.oAuthClient = oAuthClient;
        this.oidcAuthenticationHelper = oidcAuthenticationHelper;
        this.onBehalfOfUsernameHolder = onBehalfOfUsernameHolder;
        this.applicationTokenHolder = applicationTokenHolder;
        this.oidcConfiguration = oidcConfiguration;
    }

    public TokenDetails getApplicationTokenDetails() {
        UserKey user = getRunOnBehalfOfUser();
        return getApplicationTokenDetailsForUser(user);
    }

    UserKey getRunOnBehalfOfUser() {
        UserKey user = onBehalfOfUsernameHolder.getUser();
        if (user == null) {
            user = new UserKey(oidcConfiguration.getUsername(), oidcConfiguration.getDefaultRealm());
            logger.debug("run on behalf of user is not specified, default user: {} will be used then", user);
        } else {
            logger.debug("run on behalf of user: {}", user);
        }
        return user;
    }

    TokenDetails getApplicationTokenDetailsForUser(UserKey user) {
        TokenDetails tokenDetails = applicationTokenHolder.getTokenDetails(user);
        if (tokenDetails == null || tokenDetails.isEmpty()) {
            logger.info("run on behalf of user: {}, it's token is empty in application token holder", user);
            tokenDetails = oAuthClient.obtainTokenDetailsByRunOnBehalfOfUserCredentials(user.getLogin(),
                    user.getRealm());
        } else if (oidcAuthenticationHelper.isTokenExpiredOrShouldBeRefreshed(tokenDetails)) {
            logger.info("run on behalf of user: {}, it's token should be updated using refresh token", user);
            tokenDetails = retrieveUpdatedUsersTokenDetails(user, tokenDetails);
        } else {
            logger.debug("run on behalf of user: {}, using token from application token holder, it is ok", user);
        }
        return tokenDetails;
    }

    synchronized TokenDetails retrieveUpdatedUsersTokenDetails(UserKey user, TokenDetails tokenDetails) {
        try {
            String refreshToken = tokenDetails.getRefreshToken();
            TokenDetails updatedTokenDetails = oAuthClient.obtainTokenDetailsByRefreshToken(refreshToken);
            applicationTokenHolder.setTokenDetails(user, tokenDetails);
            return updatedTokenDetails;
        } catch (ObtainRefreshTokenException e) {
            logger.error("could not obtain tokenDetails using refresh token, old one will be returned instead", e);
            return tokenDetails;
        }
    }

}
