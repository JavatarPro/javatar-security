package pro.javatar.security.oidc.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import pro.javatar.security.api.SecurityService;
import pro.javatar.security.api.model.User;
import pro.javatar.security.oidc.converter.UserConverter;
import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.utils.SecurityHelper;

/**
 * @author Borys Zora
 * @version 2019-04-21
 */
@Service
public class SecurityServiceImpl implements SecurityService {

    private UserConverter userConverter;

    private TokenService tokenService;

    private SecurityHelper securityHelper;

    @Autowired
    public SecurityServiceImpl(UserConverter userConverter,
                               TokenService tokenService,
                               SecurityHelper securityHelper) {
        this.userConverter = userConverter;
        this.tokenService = tokenService;
        this.securityHelper = securityHelper;
    }

    @Override
    public User getCurrentUser() {
        TokenDetails tokenDetails = tokenService.getTokenDetails();
        if (tokenDetails == null) {
            return null;
        }
        String accessToken = tokenDetails.getAccessToken();
        User user = userConverter.toUserFromAccessToken(accessToken);
        return user;
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
        return securityHelper.getCurrentRealm();
    }

    @Override
    public String getCurrentLogin() {
        return securityHelper.getCurrentLogin();
    }
}
