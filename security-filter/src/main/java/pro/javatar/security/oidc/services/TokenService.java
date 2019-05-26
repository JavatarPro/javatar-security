package pro.javatar.security.oidc.services;

import pro.javatar.security.oidc.client.OAuthClient;
import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.exceptions.ObtainRefreshTokenException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class TokenService {

    private static final Logger logger = LoggerFactory.getLogger(TokenService.class);

    private UsersTokenService usersTokenService;

    private ApplicationTokenService applicationTokenService;

    private OAuthClient oAuthClient;

    @Autowired
    public TokenService(UsersTokenService usersTokenService,
                        ApplicationTokenService applicationTokenService,
                        OAuthClient oAuthClient) {
        this.usersTokenService = usersTokenService;
        this.applicationTokenService = applicationTokenService;
        this.oAuthClient = oAuthClient;
    }

    public TokenDetails getTokenDetails() {
        TokenDetails tokenDetails = usersTokenService.retrieveUsersTokenDetails();
        if (tokenDetails.isNotEmpty()) {
            logger.debug("return user's token details: {}", tokenDetails);
            return tokenDetails;
        }

        tokenDetails = applicationTokenService.getApplicationTokenDetails();
        if (tokenDetails.isEmpty()) {
            logger.warn("return empty token details");
        }
        return tokenDetails;
    }

    public TokenDetails getTokenByRefreshToken(String refreshToken) throws ObtainRefreshTokenException {
        return oAuthClient.obtainTokenDetailsByRefreshToken(refreshToken);
    }
}