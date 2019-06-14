package pro.javatar.security.starter.config.model;

import pro.javatar.security.api.config.SecurityConfig;

/**
 * @author Borys Zora
 * @version 2019-06-14
 */
public class VaultStorage implements SecurityConfig.Vault {

    String url;

    String client;

    String secret;

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

    public void setUrl(String url) {
        this.url = url;
    }

    public void setClient(String client) {
        this.client = client;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    @Override
    public String toString() {
        return "VaultStorage{" +
                "url='" + url + '\'' +
                ", client='" + client + '\'' +
                ", secret='" + secret + '\'' +
                '}';
    }
}
