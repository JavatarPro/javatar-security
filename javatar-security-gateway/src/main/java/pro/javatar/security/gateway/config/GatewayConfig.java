package pro.javatar.security.gateway.config;

/**
 * @author Borys Zora
 * @version 2019-06-02
 */
public interface GatewayConfig {

    Login login();

    Logout logout();

    Ui ui();

    boolean enablePostExchangeToken();

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
}
