package pro.javatar.security.starter.config.model;

import pro.javatar.security.api.config.SecurityConfig;

/**
 * @author Borys Zora
 * @version 2019-06-14
 */
public class IdentityProviderImpl implements SecurityConfig.IdentityProvider {

    private String url;
    private String client;
    private String secret;
    private String realm;

    @Override
    public String url() {
        return url;
    }

    @Override
    public String client() {
        return client;
    }

    @Override
    public String secret() {
        return secret;
    }

    @Override
    public String realm() {
        return realm;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public void setClient(String client) {
        this.client = client;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    @Override
    public String toString() {
        return "IdentityProviderImpl{" +
                "url='" + url + '\'' +
                ", client='" + client + '\'' +
                ", secret='*****'" +
                ", realm='" + realm + '\'' +
                '}';
    }
}
