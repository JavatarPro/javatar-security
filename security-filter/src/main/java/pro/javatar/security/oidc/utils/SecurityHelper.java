/*
 * Copyright (c) 2019 Javatar LLC
 * All rights reserved.
 */

package pro.javatar.security.oidc.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.services.OidcConfiguration;

/**
 * @author Andrii Murashkin / Javatar LLC
 * @version 10-03-2019
 */
@Component
public class SecurityHelper {

    private static final Logger logger = LoggerFactory.getLogger(SecurityHelper.class);

    private OidcConfiguration oidcConfiguration;

    @Autowired
    public SecurityHelper(OidcConfiguration oidcConfiguration) {
        this.oidcConfiguration = oidcConfiguration;
    }

    public String getCurrentRealm() {
        TokenDetails tokenDetails = null;
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && !(authentication instanceof AnonymousAuthenticationToken)) {
            tokenDetails = getTokenDetails(authentication);
        }
        if (tokenDetails != null) {
            return tokenDetails.getRealm();
        }
        String defaultRealm = oidcConfiguration.getDefaultRealm();
        logger.debug("Token details is null. Default realm {} will be applied.", defaultRealm);
        return defaultRealm;
    }

    public String getCurrentLogin() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            logger.debug("Current user is not authenticated.");
            throw new AccessDeniedException("User is not authenticated.");
        }
        return authentication.getName();
    }

    private TokenDetails getTokenDetails(Authentication authentication) {
        Object credentials = authentication.getCredentials();
        return credentials instanceof TokenDetails ? (TokenDetails) credentials : null;
    }
}
