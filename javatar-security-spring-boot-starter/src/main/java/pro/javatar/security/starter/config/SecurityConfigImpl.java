package pro.javatar.security.starter.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import pro.javatar.security.api.config.SecurityConfig;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Borys Zora
 * @version 2019-05-11
 */
@Configuration
@ConfigurationProperties(prefix = "javatar.security")
public class SecurityConfigImpl implements SecurityConfig {

    String logoutUrl;

    List<String> applyUrls;

    List<String> ignoreUrls;

    String redirectUrl;

    IdentityProviderImpl identityProvider;

    Boolean useReferAsRedirectUri;

    String publicKeysStorage;

    String tokenStorage;

    StorageImpl storage;

    TokenValidationImpl tokenValidation;

    StubImpl stub;

    HttpClientImpl httpClient;

    ApplicationImpl application;

    String errorDescriptionLink;

    @Override
    public String logoutUrl() {
        return logoutUrl;
    }

    @Override
    public List<String> applyUrls() {
        return applyUrls;
    }

    @Override
    public List<String> ignoreUrls() {
        return ignoreUrls;
    }

    @Override
    public String redirectUrl() {
        return redirectUrl;
    }

    @Override
    public IdentityProvider identityProvider() {
        return identityProvider;
    }

    @Override
    public Boolean useReferAsRedirectUri() {
        return useReferAsRedirectUri;
    }

    @Override
    public String publicKeysStorage() {
        return publicKeysStorage;
    }

    @Override
    public String tokenStorage() {
        return tokenStorage;
    }

    @Override
    public StorageImpl storage() {
        return storage;
    }

    @Override
    public TokenValidation tokenValidation() {
        return tokenValidation;
    }

    @Override
    public Stub stub() {
        return stub;
    }

    @Override
    public HttpClient httpClient() {
        return httpClient;
    }

    @Override
    public Application application() {
        return application;
    }

    @Override
    public String errorDescriptionLink() {
        return errorDescriptionLink;
    }

    public String getLogoutUrl() {
        return logoutUrl;
    }

    public void setLogoutUrl(String logoutUrl) {
        this.logoutUrl = logoutUrl;
    }

    public List<String> getApplyUrls() {
        return applyUrls;
    }

    public void setApplyUrls(List<String> applyUrls) {
        this.applyUrls = applyUrls;
    }

    public List<String> getIgnoreUrls() {
        return ignoreUrls;
    }

    public void setIgnoreUrls(List<String> ignoreUrls) {
        this.ignoreUrls = ignoreUrls;
    }

    public String getRedirectUrl() {
        return redirectUrl;
    }

    public void setRedirectUrl(String redirectUrl) {
        this.redirectUrl = redirectUrl;
    }

    public IdentityProviderImpl getIdentityProvider() {
        return identityProvider;
    }

    public void setIdentityProvider(IdentityProviderImpl identityProvider) {
        this.identityProvider = identityProvider;
    }

    public Boolean getUseReferAsRedirectUri() {
        return useReferAsRedirectUri;
    }

    public void setUseReferAsRedirectUri(Boolean useReferAsRedirectUri) {
        this.useReferAsRedirectUri = useReferAsRedirectUri;
    }

    public String getPublicKeysStorage() {
        return publicKeysStorage;
    }

    public void setPublicKeysStorage(String publicKeysStorage) {
        this.publicKeysStorage = publicKeysStorage;
    }

    public String getTokenStorage() {
        return tokenStorage;
    }

    public void setTokenStorage(String tokenStorage) {
        this.tokenStorage = tokenStorage;
    }

    public void setStorage(StorageImpl storage) {
        this.storage = storage;
    }

    public void setTokenValidation(TokenValidationImpl tokenValidation) {
        this.tokenValidation = tokenValidation;
    }

    public void setStub(StubImpl stub) {
        this.stub = stub;
    }

    public void setHttpClient(HttpClientImpl httpClient) {
        this.httpClient = httpClient;
    }

    public void setApplication(ApplicationImpl application) {
        this.application = application;
    }

    public void setErrorDescriptionLink(String errorDescriptionLink) {
        this.errorDescriptionLink = errorDescriptionLink;
    }

    static class IdentityProviderImpl implements IdentityProvider {

        String url;
        String client;
        String secret;
        String realm;

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

    static class StorageImpl implements Storage {

        RedisStorage redis;

        InMemoryStorage inMemory;

        VaultStorage vault;

        @Override
        public Redis getRedis() {
            return redis;
        }

        @Override
        public InMemory getInMemory() {
            return inMemory;
        }

        @Override
        public Vault getVault() {
            return vault;
        }

        public void setRedis(RedisStorage redis) {
            this.redis = redis;
        }

        public void setInMemory(InMemoryStorage inMemory) {
            this.inMemory = inMemory;
        }

        public void setVault(VaultStorage vault) {
            this.vault = vault;
        }

        @Override
        public String toString() {
            return "StorageImpl{" +
                    "redis=" + redis +
                    ", inMemory=" + inMemory +
                    ", vault=" + vault +
                    '}';
        }
    }

    static class RedisStorage implements Redis {

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

    static class InMemoryStorage implements InMemory {

        HashMap<String, String> publicKeys;

        @Override
        public Map<String, String> publicKeys() {
            return publicKeys;
        }

        public void setPublicKeys(HashMap<String, String> publicKeys) {
            this.publicKeys = publicKeys;
        }

        @Override
        public String toString() {
            return "InMemoryStorage{" +
                    "publicKeys=" + publicKeys +
                    '}';
        }
    }

    static class VaultStorage implements Vault {

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

    static class TokenValidationImpl implements TokenValidation {

        Boolean checkTokenIsActive;
        Boolean skipRefererCheck;
        Boolean checkTokenType;
        Boolean realmRequired;

        @Override
        public Boolean checkTokenIsActive() {
            return checkTokenIsActive;
        }

        @Override
        public Boolean skipRefererCheck() {
            return skipRefererCheck;
        }

        @Override
        public Boolean checkTokenType() {
            return checkTokenType;
        }

        @Override
        public Boolean realmRequired() {
            return realmRequired;
        }

        public void setCheckTokenIsActive(Boolean checkTokenIsActive) {
            this.checkTokenIsActive = checkTokenIsActive;
        }

        public void setSkipRefererCheck(Boolean skipRefererCheck) {
            this.skipRefererCheck = skipRefererCheck;
        }

        public void setCheckTokenType(Boolean checkTokenType) {
            this.checkTokenType = checkTokenType;
        }

        public void setRealmRequired(Boolean realmRequired) {
            this.realmRequired = realmRequired;
        }

        @Override
        public String toString() {
            return "TokenValidationImpl{" +
                    "checkTokenIsActive=" + checkTokenIsActive +
                    ", skipRefererCheck=" + skipRefererCheck +
                    ", checkTokenType=" + checkTokenType +
                    ", realmRequired=" + realmRequired +
                    '}';
        }
    }

    static class StubImpl implements Stub {

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

    static class HttpClientImpl implements HttpClient {

        List<String> applyUrls;

        List<String> ignoreUrls;

        @Override
        public List<String> applyUrls() {
            return applyUrls;
        }

        @Override
        public List<String> ignoreUrls() {
            return ignoreUrls;
        }

        public void setApplyUrls(List<String> applyUrls) {
            this.applyUrls = applyUrls;
        }

        public void setIgnoreUrls(List<String> ignoreUrls) {
            this.ignoreUrls = ignoreUrls;
        }

        @Override
        public String toString() {
            return "HttpClientImpl{" +
                    "applyUrls=" + applyUrls +
                    ", ignoreUrls=" + ignoreUrls +
                    '}';
        }
    }

    static class ApplicationImpl implements Application {

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

    @Override
    public String toString() {
        return "SecurityConfigImpl{" +
                "logoutUrl='" + logoutUrl + '\'' +
                ", applyUrls=" + applyUrls +
                ", ignoreUrls=" + ignoreUrls +
                ", redirectUrl='" + redirectUrl + '\'' +
                '}';
    }

}
