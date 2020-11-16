package pro.javatar.security.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

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

    RealmDetectionImpl realmDetection;

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
    public Duration tokenRefreshInterval() {
        return tokenRefreshInterval;
    }

    @Override
    public DevMode devMode() {
        return devMode;
    }

    @Override
    public RealmDetection realmDetection() {
        return realmDetection;
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

    public void setTokenRefreshInterval(Duration tokenRefreshInterval) {
        this.tokenRefreshInterval = tokenRefreshInterval;
    }

    public void setDevMode(DevModeImpl devMode) {
        this.devMode = devMode;
    }

    public GatewayConfigImpl setRealmDetection(RealmDetectionImpl realmDetection) {
        this.realmDetection = realmDetection;
        return this;
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

    static class RealmDetectionImpl implements RealmDetection {

        String defaultRealm;

        Map<String, String> subdomainAliases = new HashMap<>();

        @Override
        public String defaultRealm() {
            return defaultRealm;
        }

        @Override
        public boolean isAlias(String subdomain) {
            if(subdomain == null) return false;
            return subdomainAliases.containsKey(subdomain);
        }

        @Override
        public String getRealmBySubdomainAlias(String alias) {
            return subdomainAliases.get(alias);
        }

        public RealmDetectionImpl setDefaultRealm(String defaultRealm) {
            this.defaultRealm = defaultRealm;
            return this;
        }

        public RealmDetectionImpl setSubdomainAliases(Map<String, String> subdomainAliases) {
            this.subdomainAliases = subdomainAliases;
            return this;
        }

        @Override
        public String toString() {
            return "RealmDetectionImpl{" +
                    "defaultRealm='" + defaultRealm + '\'' +
                    ", subdomainAliases=" + subdomainAliases +
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
                ", realmDetection=" + realmDetection +
                '}';
    }
}
