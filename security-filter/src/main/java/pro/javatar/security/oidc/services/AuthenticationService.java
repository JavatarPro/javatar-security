package pro.javatar.security.oidc.services;

import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.exceptions.ObtainRefreshTokenException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationService.class);

    private TokenService tokenService;

    private OidcAuthenticationHelper oidcAuthenticationHelper;

    @Autowired
    public AuthenticationService(TokenService tokenService,
                                 OidcAuthenticationHelper oidcAuthenticationHelper) {
        this.tokenService = tokenService;
        this.oidcAuthenticationHelper = oidcAuthenticationHelper;
    }

    public void authenticateByTokenDetails(TokenDetails tokenDetails) {
        logger.debug("authenticateByTokenDetails: {}", tokenDetails);
        oidcAuthenticationHelper.authenticateCurrentThread(tokenDetails);
    }

    public void authenticateByRefreshToken(String refreshToken) throws ObtainRefreshTokenException {
        logger.debug("authenticateByRefreshToken: {}", refreshToken);
        TokenDetails tokenDetails = tokenService.getTokenByRefreshToken(refreshToken);
        authenticateByTokenDetails(tokenDetails);
    }
}
