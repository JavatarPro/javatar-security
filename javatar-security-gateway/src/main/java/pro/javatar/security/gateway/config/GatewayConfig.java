package pro.javatar.security.gateway.config;

import java.time.Duration;

/**
 * @author Borys Zora
 * @version 2019-06-02
 */
public interface GatewayConfig {

    Login login();

    Logout logout();

    Ui ui();

    boolean enablePostExchangeToken();

    Duration tokenRefreshInterval();

    DevMode devMode();

    interface Ui {

        String pathPrefix();

    }

    interface Login {

        Boolean enabled();

        String redirectUrl();
    }

    interface Logout {

        Boolean enabled();

        String redirectUrl();

    }

    interface DevMode {

        Boolean enabled();

        Boolean disableTokenIdSecuredCookies();

    }
}
