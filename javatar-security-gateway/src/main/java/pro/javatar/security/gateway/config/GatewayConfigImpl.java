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

    @Override
    public Login login() {
        return login;
    }

    @Override
    public Logout logout() {
        return logout;
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
