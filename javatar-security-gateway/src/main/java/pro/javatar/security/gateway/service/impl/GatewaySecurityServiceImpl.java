package pro.javatar.security.gateway.service.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import pro.javatar.secret.storage.api.SecretStorageService;
import pro.javatar.secret.storage.api.model.SecretTokenDetails;
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
import java.util.UUID;

/**
 * @author Borys Zora
 * @version 2019-06-01
 */
@Service
public class GatewaySecurityServiceImpl implements GatewaySecurityService {

    public static final String TOKEN_ID = "tokenID";

    private static final Logger logger = LoggerFactory.getLogger(GatewaySecurityServiceImpl.class);

    private AuthService authService;

    private SecretStorageService secretService;

    @Autowired
    public GatewaySecurityServiceImpl(AuthService authService,
                                      SecretStorageService secretService) {
        this.authService = authService;
        this.secretService = secretService;
    }

    @Override
    public String login(AuthRequestBO authRequest,
                        HttpServletRequest request,
                        HttpServletResponse response) throws LoginException {
        try {
            TokenInfoBO authToken = authService.issueTokens(authRequest);

            String realm = authRequest.getRealm();
            String ipAddress = request.getRemoteAddr();
            SecretTokenDetails secretToken = getSecretTokenDetails(realm, ipAddress, authToken);

            String correlationId = UUID.randomUUID().toString();
            secretService.put(correlationId, secretToken);

            addCookies(correlationId, response);
            return correlationId;
        } catch (IssueTokensException e) {
            throw new LoginException(e.getMessage());
        }
    }

    private void addCookies(String correlationId, HttpServletResponse response) {
        Cookie cookie = CookieUtil.createSecureCookie(TOKEN_ID, correlationId);
        logger.debug(":: Set secret key as cookie {}", cookie);
        response.addCookie(cookie);
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

    private SecretTokenDetails getSecretTokenDetails(String realm,
                                                     String ipAddress,
                                                     TokenInfoBO authToken) {
        SecretTokenDetails secretToken = new SecretTokenDetails();
        secretToken.setAccessToken(authToken.getAccessToken());
        secretToken.setRefreshToken(authToken.getRefreshToken());
        secretToken.setRealm(realm);
        String sessionToken = UUID.randomUUID().toString();
        secretToken.setSessionId(sessionToken);
        secretToken.setIpAddress(ipAddress);
        return secretToken;
    }
}
