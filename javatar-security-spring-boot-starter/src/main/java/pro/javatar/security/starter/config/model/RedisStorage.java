package pro.javatar.security.starter.config.model;

import pro.javatar.security.api.config.SecurityConfig;

import java.time.Duration;

/**
 * @author Borys Zora
 * @version 2019-06-14
 */
public class RedisStorage implements SecurityConfig.Redis {

    String host;

    Integer port;

    String password;

    Duration expiration;

    @Override
    public String host() {
        return host;
    }

    @Override
    public Integer port() {
        return port;
    }

    @Override
    public String password() {
        return password;
    }

    @Override
    public Duration expiration() {
        return expiration;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public void setPort(Integer port) {
        this.port = port;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setExpiration(Duration expiration) {
        this.expiration = expiration;
    }

    @Override
    public String toString() {
        return "RedisStorage{" +
                "host='" + host + '\'' +
                ", port=" + port +
                ", expiration=" + expiration +
                ", password='****'" +
                '}';
    }
}
