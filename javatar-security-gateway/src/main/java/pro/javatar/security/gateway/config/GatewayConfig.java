package pro.javatar.security.gateway.config;

import java.time.Duration;

/**
 * @author Borys Zora
 * @version 2019-06-02
 */
public interface GatewayConfig {

    Boolean loginEnabled();

    Boolean logoutEnabled();

    String uiPathPrefix();

    // temporary to support current functionality
    @Deprecated
    boolean enablePostExchangeToken();

    Duration tokenRefreshInterval();

    DevMode devMode();

    interface DevMode {

        Boolean enabled();

        Boolean disableTokenIdSecuredCookies();

    }
}
