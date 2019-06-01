package pro.javatar.security.gateway.service.api;

import pro.javatar.security.api.model.AuthRequestBO;
import pro.javatar.security.api.model.TokenInfoBO;
import pro.javatar.security.gateway.exception.LoginException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Gateway exchange token service used to hide token from the end user and set into cookies only UUID token.
 *
 * @author Serhii Petrychenko
 * @author Borys Zora
 * @version 2019-06-01
 */
public interface GatewaySecurityService {

    String login(AuthRequestBO request, HttpServletResponse response) throws LoginException;

    String exchangeToken(HttpServletResponse response);

    TokenInfoBO exchangeToken(HttpServletRequest request);

    void logout(HttpServletRequest request, HttpServletResponse response);

}
