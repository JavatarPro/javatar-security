package pro.javatar.security.starter.config.model;

import pro.javatar.security.api.config.SecurityConfig;

/**
 * @author Borys Zora
 * @version 2019-06-14
 */
public class RedirectImpl implements SecurityConfig.Redirect {

    boolean enabled;

    String redirectUrl;

    @Override
    public boolean enabled() {
        return enabled;
    }

    @Override
    public String redirectUrl() {
        return redirectUrl;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public void setRedirectUrl(String redirectUrl) {
        this.redirectUrl = redirectUrl;
    }

}