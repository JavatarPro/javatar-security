package pro.javatar.security.starter.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import pro.javatar.security.api.config.SecurityConfig;
import pro.javatar.security.starter.config.model.*;

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

    private static TokenValidation defaultTokenValidation = new TokenValidationImpl();

    List<String> applyUrls;

    List<String> ignoreUrls;

    RedirectImpl redirect;

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
    public List<String> applyUrls() {
        return applyUrls;
    }

    @Override
    public List<String> ignoreUrls() {
        return ignoreUrls;
    }

    @Override
    public Redirect redirect() {
        if (redirect == null) {
            return new RedirectImpl();
        }
        return redirect;
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
        if (tokenValidation == null) {
            return defaultTokenValidation;
        }
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

    @Override
    public String toString() {
        return "SecurityConfigImpl{" +
                "applyUrls=" + applyUrls +
                ", ignoreUrls=" + ignoreUrls +
                ", redirect='" + redirect + '\'' +
                ", identityProvider=" + identityProvider +
                ", useReferAsRedirectUri=" + useReferAsRedirectUri +
                ", publicKeysStorage='" + publicKeysStorage + '\'' +
                ", tokenStorage='" + tokenStorage + '\'' +
                ", storage=" + storage +
                ", tokenValidation=" + tokenValidation +
                ", stub=" + stub +
                ", httpClient=" + httpClient +
                ", application=" + application +
                ", errorDescriptionLink='" + errorDescriptionLink + '\'' +
                '}';
    }

}
