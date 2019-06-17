package pro.javatar.security.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * @author Borys Zora
 * @version 2019-06-02
 */
//@Configuration
@ConfigurationProperties(prefix = "javatar.security.gateway")
public class GatewayConfigImpl implements GatewayConfig {

    LoginImpl login;

    LogoutImpl logout;

    boolean enablePostExchangeToken = true;

    UiImpl ui;

    @Override
    public Login login() {
        return login;
    }

    @Override
    public Logout logout() {
        return logout;
    }

    @Override
    public boolean enablePostExchangeToken() {
        return enablePostExchangeToken;
    }

    @Override
    public Ui ui() {
        return ui;
    }

    public void setLogin(LoginImpl login) {
        this.login = login;
    }

    public void setLogout(LogoutImpl logout) {
        this.logout = logout;
    }

    public void setEnablePostExchangeToken(boolean enablePostExchangeToken) {
        this.enablePostExchangeToken = enablePostExchangeToken;
    }

    public void setUi(UiImpl ui) {
        this.ui = ui;
    }

    static class UiImpl implements Ui {

        String pathPrefix;

        @Override
        public String pathPrefix() {
            return pathPrefix;
        }

        public void setPathPrefix(String pathPrefix) {
            this.pathPrefix = pathPrefix;
        }

    }

    static class LoginImpl implements Login {

        Boolean enabled;

        String redirectUrl;

        @Override
        public Boolean enabled() {
            return enabled;
        }

        @Override
        public String redirectUrl() {
            return redirectUrl;
        }

        public void setEnabled(Boolean enabled) {
            this.enabled = enabled;
        }

        public void setRedirectUrl(String redirectUrl) {
            this.redirectUrl = redirectUrl;
        }

        @Override
        public String toString() {
            return "LoginImpl{" +
                    "enabled=" + enabled +
                    ", redirectUrl='" + redirectUrl + '\'' +
                    '}';
        }
    }

    static class LogoutImpl implements Logout {

        Boolean enabled;

        String redirectUrl;

        @Override
        public Boolean enabled() {
            return enabled;
        }

        @Override
        public String redirectUrl() {
            return redirectUrl;
        }

        public void setEnabled(Boolean enabled) {
            this.enabled = enabled;
        }

        public void setRedirectUrl(String redirectUrl) {
            this.redirectUrl = redirectUrl;
        }

        @Override
        public String toString() {
            return "LogoutImpl{" +
                    "enabled=" + enabled +
                    ", redirectUrl='" + redirectUrl + '\'' +
                    '}';
        }
    }

}
