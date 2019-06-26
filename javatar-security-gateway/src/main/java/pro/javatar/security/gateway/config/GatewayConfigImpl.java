package pro.javatar.security.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * @author Borys Zora
 * @version 2019-06-02
 */
@ConfigurationProperties(prefix = "javatar.security.gateway")
public class GatewayConfigImpl implements GatewayConfig {

    // fields

    LoginImpl login = new LoginImpl(false, null);

    LogoutImpl logout = new LogoutImpl(false, null);

    boolean enablePostExchangeToken = true;

    Duration tokenRefreshInterval = Duration.parse("PT7M");

    UiImpl ui;

    DevModeImpl devMode;

    // interface impl

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
    public Duration tokenRefreshInterval() {
        return tokenRefreshInterval;
    }

    @Override
    public Ui ui() {
        return ui;
    }

    @Override
    public DevMode devMode() {
        return devMode;
    }

    // setters

    public void setLogin(LoginImpl login) {
        this.login = login;
    }

    public void setLogout(LogoutImpl logout) {
        this.logout = logout;
    }

    public void setEnablePostExchangeToken(boolean enablePostExchangeToken) {
        this.enablePostExchangeToken = enablePostExchangeToken;
    }

    public void setTokenRefreshInterval(Duration tokenRefreshInterval) {
        this.tokenRefreshInterval = tokenRefreshInterval;
    }

    public void setUi(UiImpl ui) {
        this.ui = ui;
    }

    public void setDevMode(DevModeImpl devMode) {
        this.devMode = devMode;
    }

    // classes

    static class UiImpl implements Ui {

        String pathPrefix;

        @Override
        public String pathPrefix() {
            return pathPrefix;
        }

        public void setPathPrefix(String pathPrefix) {
            this.pathPrefix = pathPrefix;
        }

        @Override
        public String toString() {
            return "UiImpl{" +
                    "pathPrefix='" + pathPrefix + '\'' +
                    '}';
        }
    }

    static class LoginImpl implements Login {

        Boolean enabled = false;

        String redirectUrl;

        public LoginImpl() {}

        public LoginImpl(Boolean enabled, String redirectUrl) {
            this.enabled = enabled;
            this.redirectUrl = redirectUrl;
        }

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

        public LogoutImpl() {}

        public LogoutImpl(Boolean enabled, String redirectUrl) {
            this.enabled = enabled;
            this.redirectUrl = redirectUrl;
        }

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

    static class DevModeImpl implements DevMode {

        Boolean enabled;

        Boolean disableTokenIdSecuredCookies = true;

        @Override
        public Boolean enabled() {
            return enabled;
        }

        @Override
        public Boolean disableTokenIdSecuredCookies() {
            return disableTokenIdSecuredCookies;
        }

        public void setEnabled(Boolean enabled) {
            this.enabled = enabled;
        }

        public void setDisableTokenIdSecuredCookies(Boolean disableTokenIdSecuredCookies) {
            this.disableTokenIdSecuredCookies = disableTokenIdSecuredCookies;
        }

        @Override
        public String toString() {
            return "DevModeImpl{" +
                    "enabled=" + enabled +
                    ", disableTokenIdSecuredCookies=" + disableTokenIdSecuredCookies +
                    '}';
        }
    }

    @Override
    public String toString() {
        return "GatewayConfigImpl{" +
                "login=" + login +
                ", logout=" + logout +
                ", enablePostExchangeToken=" + enablePostExchangeToken +
                ", tokenRefreshInterval=" + tokenRefreshInterval +
                ", ui=" + ui +
                '}';
    }
}
