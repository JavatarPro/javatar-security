package pro.javatar.security.api.config;

import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * All security configuration should be provided by this interface to any filter
 *
 * @author Borys Zora
 * @version 2019-05-08
 */
public interface SecurityConfig {

    List<String> applyUrls();

    // TODO forbidden urls, issue SEC-5

    List<String> ignoreUrls();

    SecurityFilter securityFilter();

    boolean isSkipRefererCheck();

    Redirect redirect();

    IdentityProvider identityProvider();

    default IdentityProviderAdmin identityProviderAdmin() {
        return () -> identityProvider().url();
    }

    Boolean useReferAsRedirectUri();

    String publicKeysStorage();

    String tokenStorage();

    Storage storage();

    TokenValidation tokenValidation();

    Stub stub();

    HttpClient httpClient();

    Application application();

    String errorDescriptionLink();

    interface SecurityFilter {

        boolean isAnonymousAllowed();

        boolean isJwtBearerFilterEnable();

        boolean isJwtBearerTokenOtherAuthenticationAllowed();
    }

    interface Redirect {

        boolean enabled();

        boolean isUseReferAsRedirectUri();

        String redirectUrl();

    }

    interface IdentityProvider {

        String url();

        String client();

        String secret();

        String realm();
    }

    interface IdentityProviderAdmin {

        String url();

        default String client() {
            return "admin-cli";
        }

        default String realm() {
            return "master";
        }

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
