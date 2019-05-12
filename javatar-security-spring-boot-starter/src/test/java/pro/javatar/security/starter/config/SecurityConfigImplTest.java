package pro.javatar.security.starter.config;

import org.junit.Ignore;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import pro.javatar.security.api.config.SecurityConfig;
import pro.javatar.security.starter.SpringBootApp;

import java.time.Duration;
import java.util.*;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * @author Borys Zora
 * @version 2019-05-11
 */
@SpringBootTest(classes = {SpringBootApp.class})
class SecurityConfigImplTest {

    @Autowired
    SecurityConfig config;

    @Test
    void logoutUrl() {
        assertThat(config.logoutUrl(), is("/logout"));
    }

    @Test
    void applyUrls() {
        List<String> actual = new ArrayList<>(config.applyUrls());
        List<String> expected = new ArrayList<>();
        expected.add("/work/*");
        expected.add("/message/*");
        Collections.sort(actual);
        Collections.sort(expected);
        assertThat(actual, is(expected));
    }

    @Test
    void ignoreUrls() {
        List<String> actual = new ArrayList<>(config.ignoreUrls());
        List<String> expected = new ArrayList<>();
        expected.add("/work/profile/*");
        expected.add("/message/channel/*");
        Collections.sort(actual);
        Collections.sort(expected);
        assertThat(actual, is(expected));
    }

    @Test
    void redirectUrl() {
        assertThat(config.redirectUrl(), is("/login.html"));
    }

    @Test
    void identityProvider() {
        SecurityConfig.IdentityProvider actual = config.identityProvider();
        assertThat(actual.url(), is("https://some-host:8080"));
        assertThat(actual.client(), is("api-gateway-service"));
        assertThat(actual.secret(), is("a78f09a1-ac49-4855-b3a4-dca4ce6e4cb8"));
        assertThat(actual.realm(), is("dev"));
    }

    @Test
    void useReferAsRedirectUri() {
        assertThat(config.useReferAsRedirectUri(), is(true));
    }

    @Test
    void publicKeysStorage() {
        assertThat(config.publicKeysStorage(), is("in-memeory"));
    }

    @Test
    void tokenStorage() {
        assertThat(config.tokenStorage(), is("redis"));
    }

    @Test
    void storage() {
        SecurityConfig.Storage storage = config.storage();

        SecurityConfig.Redis redis = storage.getRedis();
        assertThat(redis.host(), is("localhost"));
        assertThat(redis.port(), is(6379));
        assertThat(redis.password(), is("37339ebe-0593-4e6f-b88c-1d3898be6a75"));

        SecurityConfig.InMemory inMemory = storage.getInMemory();
        Map<String, String> actualInMemory = inMemory.publicKeys();
        Map<String, String> expectedInMemory = new HashMap<>();
        expectedInMemory.put("dev", "aldkfjasdlfjalsdfkjasl");
        expectedInMemory.put("qa", "klkmlkjlksdfglkmdflsakdf");
        assertThat(actualInMemory, is(expectedInMemory));

        SecurityConfig.Vault vault = storage.getVault();
        assertThat(vault.url(), is("http://localhost:8200"));
        assertThat(vault.client(), is("vault-client"));
        assertThat(vault.secret(), is("some-vault-secret"));
    }

    @Test
    void tokenValidation() {
        SecurityConfig.TokenValidation actual = config.tokenValidation();
        assertThat(actual.checkTokenIsActive(), is(true));
        assertThat(actual.checkTokenType(), is(true));
        assertThat(actual.realmRequired(), is(true));
        assertThat(actual.skipRefererCheck(), is(true));
    }

    @Test
    void stub() {
        SecurityConfig.Stub stub = config.stub();
        assertThat(stub.enabled(), is(true));
        assertThat(stub.accessToken(), is("adlfkjasd"));
    }

    @Test
    void httpClient() {
        SecurityConfig.HttpClient httpClient = config.httpClient();

        List<String> applyUrls = new ArrayList<>(httpClient.applyUrls());
        List<String> expectedApplyUrls = new ArrayList<>();
        expectedApplyUrls.add("/work/*");
        expectedApplyUrls.add("/message/*");
        expectedApplyUrls.add("/test/*");
        Collections.sort(applyUrls);
        Collections.sort(expectedApplyUrls);
        assertThat(applyUrls, is(expectedApplyUrls));

        List<String> ignoreUrls = new ArrayList<>(httpClient.ignoreUrls());
        List<String> expectedIgnoreUrls = new ArrayList<>();
        expectedIgnoreUrls.add("/message/channel/*");
        expectedIgnoreUrls.add("/work/profile/*");
        Collections.sort(ignoreUrls);
        Collections.sort(expectedIgnoreUrls);
        assertThat(ignoreUrls, is(expectedIgnoreUrls));
    }

    @Test
    void application() {
        SecurityConfig.Application app = config.application();
        assertThat(app.user(), is("admin"));
        assertThat(app.password(), is("se(r@t"));
        assertThat(app.tokenShouldBeRefreshedDuration(), is(Duration.parse("PT1M15S")));
        assertThat(app.allowOtherAuthentication(), is(false));
        assertThat(app.allowAnonymous(), is(true));

        SecurityConfig.Application.Realm realm = app.realm();
        assertThat(realm.urlPattern(), is("/{realm}/{service}/some/url"));
        assertThat(realm.requestParamName(), is("realm"));
        assertThat(realm.headerName(), is("X-REALM"));
        assertThat(realm.refreshHeaderName(), is("X-REFRESH-TOKEN"));
    }

}