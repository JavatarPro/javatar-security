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

    Boolean loginEnabled = false;

    Boolean logoutEnabled = false;

    Duration tokenRefreshInterval = Duration.parse("PT7M");

    String uiPathPrefix;

    DevModeImpl devMode;

    // temporary field
    boolean enablePostExchangeToken = true;

    // interface impl

    @Override
    public Boolean loginEnabled() {
        return loginEnabled;
    }

    @Override
    public Boolean logoutEnabled() {
        return logoutEnabled;
    }

    @Override
    public String uiPathPrefix() {
        return uiPathPrefix;
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
    public DevMode devMode() {
        return devMode;
    }

    // setters

    public void setLoginEnabled(Boolean loginEnabled) {
        this.loginEnabled = loginEnabled;
    }

    public void setLogoutEnabled(Boolean logoutEnabled) {
        this.logoutEnabled = logoutEnabled;
    }

    public void setUiPathPrefix(String uiPathPrefix) {
        this.uiPathPrefix = uiPathPrefix;
    }

    public void setEnablePostExchangeToken(boolean enablePostExchangeToken) {
        this.enablePostExchangeToken = enablePostExchangeToken;
    }

    public void setTokenRefreshInterval(Duration tokenRefreshInterval) {
        this.tokenRefreshInterval = tokenRefreshInterval;
    }

    public void setDevMode(DevModeImpl devMode) {
        this.devMode = devMode;
    }

    // classes

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
                "loginEnabled=" + loginEnabled +
                ", logoutEnabled=" + logoutEnabled +
                ", tokenRefreshInterval=" + tokenRefreshInterval +
                ", uiPathPrefix='" + uiPathPrefix + '\'' +
                ", devMode=" + devMode +
                ", enablePostExchangeToken=" + enablePostExchangeToken +
                '}';
    }
}
