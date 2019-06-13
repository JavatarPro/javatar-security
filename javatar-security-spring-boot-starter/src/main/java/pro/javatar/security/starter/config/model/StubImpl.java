package pro.javatar.security.starter.config.model;

import pro.javatar.security.api.config.SecurityConfig;

/**
 * @author Borys Zora
 * @version 2019-06-14
 */
public class StubImpl implements SecurityConfig.Stub {

    Boolean enabled;

    String accessToken;

    @Override
    public Boolean enabled() {
        if (enabled == null) {
            return false;
        }
        return enabled;
    }

    @Override
    public String accessToken() {
        return accessToken;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    @Override
    public String toString() {
        return "StubImpl{" +
                "enabled=" + enabled +
                ", accessToken='" + accessToken + '\'' +
                '}';
    }

}