package pro.javatar.security.gateway.service.api;

import pro.javatar.security.api.model.AuthRequestBO;
import pro.javatar.security.gateway.exception.LoginException;
import pro.javatar.security.gateway.model.GatewayResponse;
import pro.javatar.security.gateway.model.HeaderMapRequestWrapper;

import javax.servlet.ServletRequest;
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

    /**
     * User login to specific realm by user email & password.
     * Cookies will be added to response with HTTPOnly & Secured flags
     *
     * @param authRequest {@link AuthRequestBO} - actual user's login request, with data provided by him,
     *                                         except realm could be used as default for api-gateway
     * @param request {@link HttpServletRequest} - whole servlet request to retrieve more data about request
     * @param response {@link HttpServletResponse} - to add cookies in it
     * @return rootToken {@link String} that means session fro all user requests
     * @throws LoginException
     */
    String login(AuthRequestBO authRequest, HttpServletRequest request, HttpServletResponse response)
            throws LoginException;

    void exchangeToken(GatewayResponse response);

    void appendSecurityHeaders(HeaderMapRequestWrapper requestWrapper);

    void logout(HttpServletRequest request, HttpServletResponse response);

    boolean shouldApplyUrl(ServletRequest request);

}
