package pro.javatar.security.oidc.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import pro.javatar.security.api.SecurityService;
import pro.javatar.security.api.config.SecurityConfig;
import pro.javatar.security.api.model.User;
import pro.javatar.security.oidc.converter.UserConverter;
import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.utils.SecurityHelper;

import static pro.javatar.security.oidc.utils.StringUtils.isBlank;

/**
 * @author Borys Zora
 * @version 2019-04-21
 */
@Service
public class SecurityServiceImpl implements SecurityService {

    private static final Logger logger = LoggerFactory.getLogger(SecurityServiceImpl.class);

    private UserConverter userConverter;

    private UsersTokenService tokenService;

    private SecurityHelper securityHelper;

    private SecurityConfig securityConfig;

    @Autowired
    public SecurityServiceImpl(UserConverter userConverter,
                               UsersTokenService tokenService,
                               SecurityHelper securityHelper,
                               SecurityConfig securityConfig) {
        this.userConverter = userConverter;
        this.tokenService = tokenService;
        this.securityHelper = securityHelper;
        this.securityConfig = securityConfig;
    }

    @Override
    public User getCurrentUser() {
        TokenDetails tokenDetails = tokenService.retrieveUsersTokenDetails();
        if (tokenDetails == null) {
            return null;
        }
        String accessToken = tokenDetails.getAccessToken();
        return getUser(accessToken);
    }

    @Override
    public String getCurrentUserId() {
        User currentUser = getCurrentUser();
        if (currentUser == null) {
            return null;
        }
        return currentUser.getId();
    }

    @Override
    public String getCurrentRealm() {
        String realm = securityHelper.getCurrentRealm();
        if (isBlank(realm)) {
            String defaultRealm = securityConfig.identityProvider().realm();
            logger.debug("Token details is blank. Default realm {} will be applied.", defaultRealm);
            return defaultRealm;
        }
        return realm;
    }

    @Override
    public String getCurrentLogin() {
        return securityHelper.getCurrentLogin();
    }

    @Override
    public User getUser(String accessToken) {
        return userConverter.toUserFromAccessToken(accessToken);
    }
}
