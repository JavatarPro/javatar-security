/*
 * Copyright (c) 2019 Javatar LLC
 * All rights reserved.
 */
package pro.javatar.security.api;

import pro.javatar.security.api.exception.IssueTokensException;
import pro.javatar.security.api.model.AuthRequestBO;
import pro.javatar.security.api.model.TokenInfoBO;
import pro.javatar.security.oidc.exceptions.ObtainRefreshTokenException;

/**
 * External auth calls.
 * e.g. to keycloak
 *
 * @author Andrii Murashkin / Javatar LLC
 * @version 06-03-2019
 */
public interface AuthService {

    TokenInfoBO issueTokens(AuthRequestBO authRequest) throws IssueTokensException;

    TokenInfoBO reIssueTokens(String refreshToken) throws ObtainRefreshTokenException;

    TokenInfoBO issueTokensByAdmin(AuthRequestBO authRequest) throws IssueTokensException;

}
