package pro.javatar.security.gateway.service.impl.util;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import pro.javatar.security.gateway.config.GatewayConfig;

import javax.servlet.http.Cookie;

/**
 * @author Borys Zora
 * @version 2019-06-27
 */
@Service
@ConditionalOnProperty(value = "javatar.security.gateway.devMode.enabled", havingValue = "true", matchIfMissing = false)
public class CookieServiceDevModeImpl extends CookieServiceImpl {

    private GatewayConfig gatewayConfig;

    public CookieServiceDevModeImpl(GatewayConfig gatewayConfig) {
        this.gatewayConfig = gatewayConfig;
    }

    @Override
    public Cookie createSecureCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        if (!gatewayConfig.devMode().disableTokenIdSecuredCookies()) {
            cookie.setSecure(true);
        }
        return cookie;
    }

}
