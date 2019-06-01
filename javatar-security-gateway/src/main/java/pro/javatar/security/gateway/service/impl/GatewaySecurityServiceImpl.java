package pro.javatar.security.gateway.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import pro.javatar.secret.storage.api.SecretStorageService;
import pro.javatar.security.api.AuthService;
import pro.javatar.security.gateway.exception.LoginException;
import pro.javatar.security.gateway.service.api.GatewaySecurityService;
import pro.javatar.security.api.exception.IssueTokensException;
import pro.javatar.security.api.model.AuthRequestBO;
import pro.javatar.security.api.model.TokenInfoBO;
import pro.javatar.security.gateway.service.impl.util.CookieUtil;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Borys Zora
 * @version 2019-06-01
 */
public class GatewaySecurityServiceImpl implements GatewaySecurityService {

    private AuthService authService;

    private SecretStorageService secretService;

    @Autowired
    public GatewaySecurityServiceImpl(AuthService authService) {
        this.authService = authService;
    }

    @Override
    public String login(AuthRequestBO request, HttpServletResponse response) throws LoginException {
        try {
            authService.issueTokens(request);
            return null;
        } catch (IssueTokensException e) {
            throw new LoginException(e.getMessage());
        }
    }

    @Override
    public String exchangeToken(HttpServletResponse response) {
        return null;
    }

    @Override
    public TokenInfoBO exchangeToken(HttpServletRequest request) {
        return null;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        String secretKey = CookieUtil.getCookie("tokenID", cookies);
        // TODO remove parent vault key, rotate keys more frequently
        secretService.delete(secretKey);
        // TODO response send empty cookies for our token
    }

}
