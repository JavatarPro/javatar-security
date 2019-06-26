package pro.javatar.security.gateway.service.api;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Borys Zora
 * @version 2019-06-27
 */
public interface CookieService {

    String getCookie(String cookieName, Cookie[] cookies);

    void createSecureCookie(HttpServletResponse response, String key, String value);

    Cookie createSecureCookie(String key, String value);

    void removeCookie(HttpServletResponse response, String cookieName);

}
