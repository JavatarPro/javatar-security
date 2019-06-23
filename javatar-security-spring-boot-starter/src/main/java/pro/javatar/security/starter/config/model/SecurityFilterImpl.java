package pro.javatar.security.starter.config.model;

import pro.javatar.security.api.config.SecurityConfig;

/**
 * @author Borys Zora
 * @version 2019-06-22
 */
public class SecurityFilterImpl implements SecurityConfig.SecurityFilter {

    boolean anonymousAllowed = false;

    boolean jwtBearerFilterEnable = true;

    boolean jwtBearerTokenOtherAuthenticationAllowed = false;

    @Override
    public boolean isAnonymousAllowed() {
        return anonymousAllowed;
    }

    @Override
    public boolean isJwtBearerFilterEnable() {
        return jwtBearerFilterEnable;
    }

    @Override
    public boolean isJwtBearerTokenOtherAuthenticationAllowed() {
        return jwtBearerTokenOtherAuthenticationAllowed;
    }

    public void setAnonymousAllowed(boolean anonymousAllowed) {
        this.anonymousAllowed = anonymousAllowed;
    }

    public void setJwtBearerFilterEnable(boolean jwtBearerFilterEnable) {
        this.jwtBearerFilterEnable = jwtBearerFilterEnable;
    }

    public void setJwtBearerTokenOtherAuthenticationAllowed(boolean jwtBearerTokenOtherAuthenticationAllowed) {
        this.jwtBearerTokenOtherAuthenticationAllowed = jwtBearerTokenOtherAuthenticationAllowed;
    }

    @Override
    public String toString() {
        return "SecurityFilterImpl{" +
                "anonymousAllowed=" + anonymousAllowed +
                ", jwtBearerFilterEnable=" + jwtBearerFilterEnable +
                ", jwtBearerTokenOtherAuthenticationAllowed=" + jwtBearerTokenOtherAuthenticationAllowed +
                '}';
    }
}
