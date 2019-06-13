package pro.javatar.security.starter.config.model;

import pro.javatar.security.api.config.SecurityConfig;

import java.time.Duration;

/**
 * @author Borys Zora
 * @version 2019-06-14
 */
public class ApplicationImpl implements SecurityConfig.Application {

    String user;

    String password;

    Duration tokenShouldBeRefreshedDuration;

    Boolean allowOtherAuthentication;

    Boolean allowAnonymous;

    RealmImpl realm;

    @Override
    public String user() {
        return user;
    }

    @Override
    public String password() {
        return password;
    }

    @Override
    public Duration tokenShouldBeRefreshedDuration() {
        return tokenShouldBeRefreshedDuration;
    }

    @Override
    public Boolean allowOtherAuthentication() {
        return allowOtherAuthentication;
    }

    @Override
    public Boolean allowAnonymous() {
        return allowAnonymous;
    }

    @Override
    public Realm realm() {
        return realm;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setTokenShouldBeRefreshedDuration(Duration tokenShouldBeRefreshedDuration) {
        this.tokenShouldBeRefreshedDuration = tokenShouldBeRefreshedDuration;
    }

    public void setAllowOtherAuthentication(Boolean allowOtherAuthentication) {
        this.allowOtherAuthentication = allowOtherAuthentication;
    }

    public void setAllowAnonymous(Boolean allowAnonymous) {
        this.allowAnonymous = allowAnonymous;
    }

    public void setRealm(RealmImpl realm) {
        this.realm = realm;
    }

    static class RealmImpl implements Realm {

        String urlPattern;

        String requestParamName;

        String headerName;

        String refreshHeaderName;

        @Override
        public String urlPattern() {
            return urlPattern;
        }

        @Override
        public String requestParamName() {
            return requestParamName;
        }

        @Override
        public String headerName() {
            return headerName;
        }

        @Override
        public String refreshHeaderName() {
            return refreshHeaderName;
        }

        public void setUrlPattern(String urlPattern) {
            this.urlPattern = urlPattern;
        }

        public void setRequestParamName(String requestParamName) {
            this.requestParamName = requestParamName;
        }

        public void setHeaderName(String headerName) {
            this.headerName = headerName;
        }

        public void setRefreshHeaderName(String refreshHeaderName) {
            this.refreshHeaderName = refreshHeaderName;
        }

        @Override
        public String toString() {
            return "RealmImpl{" +
                    "urlPattern='" + urlPattern + '\'' +
                    ", requestParamName='" + requestParamName + '\'' +
                    ", headerName='" + headerName + '\'' +
                    ", refreshHeaderName='" + refreshHeaderName + '\'' +
                    '}';
        }
    }

    @Override
    public String toString() {
        return "ApplicationImpl{" +
                "user='" + user + '\'' +
                ", password='" + password + '\'' +
                ", tokenShouldBeRefreshedDuration=" + tokenShouldBeRefreshedDuration +
                ", allowOtherAuthentication=" + allowOtherAuthentication +
                ", allowAnonymous=" + allowAnonymous +
                ", realm=" + realm +
                '}';
    }
}