package pro.javatar.security.gateway.service.impl.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import pro.javatar.security.gateway.service.api.CookieService;

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
@Service
@ConditionalOnProperty(value = "javatar.security.gateway.dev-mode.enabled", havingValue = "false", matchIfMissing = true)
public class CookieServiceImpl implements CookieService {

    private static final Logger logger = LoggerFactory.getLogger(CookieServiceImpl.class);

    @Override
    public String getCookie(String cookieName, Cookie[] cookies) {
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

    @Override
    public void createSecureCookie(HttpServletResponse response, String key, String value) {
        Cookie secureCookie = createSecureCookie(key, value);
        logger.debug(":: Set secret key as cookie {}", secureCookie);
        response.addCookie(secureCookie);
    }

    @Override
    public Cookie createSecureCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        return cookie;
    }

    @Override
    public void removeCookie(HttpServletResponse response, String cookieName) {
        Cookie cookie = new Cookie(cookieName, null);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }

}

