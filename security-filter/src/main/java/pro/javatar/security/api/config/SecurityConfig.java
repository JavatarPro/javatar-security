package pro.javatar.security.api.config;

import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * @author Borys Zora
 * @version 2019-05-08
 */
public interface SecurityConfig {

    String logoutUrl();

    List<String> applyUrls();

    List<String> ignoreUrls();

    String redirectUrl();

    IdentityProvider identityProvider();

    Boolean useReferAsRedirectUri();

    String publicKeysStorage();

    String tokenStorage();

    Storage storage();

    TokenValidation tokenValidation();

    Stub stub();

    HttpClient httpClient();

    Application application();

    interface IdentityProvider {

        String url();

        String client();

        String secret();

        String realm();
    }

    interface Storage {

        Redis getRedis();

        InMemory getInMemory();

        Vault getVault();

    }

    interface Redis {

        String host();

        Integer port();

        String password();

        Duration expiration();

    }

    interface InMemory {

        Map<String, String> publicKeys();

    }

    interface Vault {

        String url();

        String client();

        String secret();

    }

    interface TokenValidation {

        Boolean checkTokenIsActive();

        Boolean skipRefererCheck();

        Boolean checkTokenType();

        Boolean realmRequired();

    }

    interface Stub {

        Boolean enabled();

        String accessToken();

    }

    interface HttpClient {

        List<String> applyUrls();

        List<String> ignoreUrls();

    }

    interface Application {

        String user();

        String password();

        Duration tokenShouldBeRefreshedDuration();

        Boolean allowOtherAuthentication();

        Boolean allowAnonymous();

        Realm realm();

        interface Realm {

            String urlPattern();

            String requestParamName();

            String headerName();

            String refreshHeaderName();
        }

    }

}
