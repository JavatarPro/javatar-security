package pro.javatar.security.gateway.service.impl.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Borys Zora
 * @author Andrii Murashkin
 * @author Serhii Petrychenko
 * @author kuzan
 *
 * @version 2019-05-08
 */
public class CookieUtil {
    public static String getCookie(String cookieName, Cookie[] cookies) {
        if(cookies == null){
            return "";
        }
        for (Cookie cookie : cookies) {
            if (cookie.getName().equalsIgnoreCase(cookieName)) {
                return cookie.getValue();
            }
        }
        return "";
    }

    public static Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        return cookie;
    }

    public static void removeCookie(HttpServletResponse response, String cookieName) {
        Cookie cookie = new Cookie(cookieName, null);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }
}

