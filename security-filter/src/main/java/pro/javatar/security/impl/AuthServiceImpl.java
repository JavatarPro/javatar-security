/*
 * Copyright (c) 2019 Javatar LLC
 * All rights reserved.
 */
package pro.javatar.security.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import pro.javatar.security.api.AuthService;
import pro.javatar.security.api.exception.IssueTokensException;
import pro.javatar.security.api.model.AuthRequestBO;
import pro.javatar.security.api.model.TokenInfoBO;
import pro.javatar.security.impl.coverter.AuthBOConverter;
import pro.javatar.security.oidc.client.OAuthClient;
import pro.javatar.security.oidc.exceptions.InvalidUserCredentialsAuthenticationException;
import pro.javatar.security.oidc.exceptions.RealmNotFoundAuthnticationException;
import pro.javatar.security.oidc.model.TokenDetails;

/**
 * @author Andrii Murashkin / Javatar LLC
 * @version 06-03-2019
 */
public class AuthServiceImpl implements AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);

    private OAuthClient oAuthClient;

    private AuthBOConverter authBOConverter;

    @Autowired
    public AuthServiceImpl(OAuthClient oAuthClient,
                           AuthBOConverter authBOConverter) {
        this.oAuthClient = oAuthClient;
        this.authBOConverter = authBOConverter;
    }

    @Override
    public TokenInfoBO issueTokens(AuthRequestBO authRequest) throws IssueTokensException {
        try {
            return issueTokensUsingIdentityProvider(authRequest);
        } catch (InvalidUserCredentialsAuthenticationException e) {
            logger.debug("Invalid user credentials.");
            throw new InvalidUserCredentialsAuthenticationException();
        } catch (RealmNotFoundAuthnticationException e) {
            logger.debug("Realm {} not found.", authRequest.getRealm());
            throw new RealmNotFoundAuthnticationException();
        } catch (Exception e) {
            logger.debug("issueTokens failed for authRequest: {}, trying handle exception", authRequest);
            throw new IssueTokensException(e.getMessage());
        }
    }

    private TokenInfoBO issueTokensUsingIdentityProvider(AuthRequestBO authRequest) {
        TokenDetails tokenDetails = oAuthClient.obtainTokenDetailsByApplicationCredentials(
                authRequest.getEmail(), authRequest.getPassword(), authRequest.getRealm());
        return authBOConverter.toTokenInfoBO(tokenDetails);
    }
}
