package pro.javatar.security.oidc.services.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import pro.javatar.security.api.config.SecurityConfig;
import pro.javatar.security.jwt.TokenVerifier;
import pro.javatar.security.oidc.SecurityConstants;
import pro.javatar.security.oidc.exceptions.AuthenticationException;
import pro.javatar.security.oidc.exceptions.RealmInJwtTokenNotFoundAuthenticationException;
import pro.javatar.security.oidc.exceptions.TokenSignedForOtherRealmAuthorizationException;
import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.services.api.RealmService;
import pro.javatar.security.oidc.utils.StringUtils;

import javax.servlet.http.HttpServletResponse;

/**
 * @author Borys Zora
 * @version 2019-05-25
 */
public class RealmServiceImpl implements RealmService {

    private static final Logger logger = LoggerFactory.getLogger(RealmServiceImpl.class);

    public static final ThreadLocal<String> realms = new ThreadLocal<>();

    private SecurityConfig config;

    @Autowired
    public RealmServiceImpl(SecurityConfig config) {
        this.config = config;
    }

    @Override
    public void setRealmForCurrentRequest(String realm) {
        if (StringUtils.isBlank(realm))
            return;
        logger.debug("setting up realm: {} for current request", realm);
        realms.set(realm);
    }

    @Override
    public String getRealmForCurrentRequest() {
        String realm = realms.get();
        if (StringUtils.isBlank(realm)) {
            return config.identityProvider().realm();
        }
        return realm;
    }


    @Override
    public String getRealmForCurrentRequest(HttpServletResponse response) {
        String realm = realms.get();
        if (StringUtils.isNotBlank(realm)) {
            return realm;
        }
        String responseHeaderRealm = response.getHeader(SecurityConstants.REALM_HEADER);
        return StringUtils.isNotBlank(responseHeaderRealm) ?
                responseHeaderRealm :
                config.identityProvider().realm();
    }

    @Override
    public void validateRealm(TokenDetails tokenDetails) throws TokenSignedForOtherRealmAuthorizationException {
        logger.info("Start validate realm token");
        String tokenRealm = tokenDetails.getRealm();
        // TODO
//        if (oidcConfiguration.getExcludeValidationRealm().equalsIgnoreCase(tokenRealm)) {
//            return;
//        }
        String resourceAccessRealm = getRealmForCurrentRequest();
        if (!tokenRealm.equalsIgnoreCase(resourceAccessRealm)) {
            String devMessage =
                    String.format("Token signed for %s realm, but user try to access %s realm",
                            tokenRealm, resourceAccessRealm);
            logger.error("Token signed for {} realm, but user try to access {} realm", tokenRealm, resourceAccessRealm);
            AuthenticationException e = new TokenSignedForOtherRealmAuthorizationException();
            e.setDevMessage(devMessage);
            throw e;
        }
        logger.info("Realm token validation completed successfully");
    }

    @Override
    public void removeRealmFromCurrentRequest() {
        realms.remove();
    }

    @Override
    public String getRealmFromToken(String accessToken) throws RealmInJwtTokenNotFoundAuthenticationException {
        String realm = TokenVerifier.getRealm(accessToken);
        if (StringUtils.isBlank(realm)) {
            logger.error("Unable to obtain realm from Access token.");
            throw new RealmInJwtTokenNotFoundAuthenticationException();
        }
        return realm;
    }

    public void setConfig(SecurityConfig config) {
        this.config = config;
    }
}
