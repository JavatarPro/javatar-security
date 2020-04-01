package pro.javatar.security.oidc.services;

import static junit.framework.TestCase.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pro.javatar.security.api.config.SecurityConfig;
import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.client.OAuthClient;
import pro.javatar.security.oidc.utils.JwtTokenGenerator;
import pro.javatar.security.oidc.utils.KeyUtils;

import pro.javatar.security.oidc.utils.SpringTestConfig;

import java.util.Arrays;
import java.util.UUID;

class OAuth2AuthorizationFlowServiceTest {

    private OAuthClient authClient;
    private OidcConfiguration oidcConfiguration;
    private PublicKeyCacheService publicKeyCacheService;
    private SecurityConfig securityConfig;

    @BeforeEach
    void setUp() {
        securityConfig = new SpringTestConfig().securityConfig();

        authClient = mock(OAuthClient.class);
        oidcConfiguration = mock(OidcConfiguration.class);
        publicKeyCacheService = mock(PublicKeyCacheService.class);
    }

    @Test
    void getTokenDetailsByCode() {
        String code = UUID.randomUUID().toString();
        String redirectUrl = "context/test";

        TokenDetails tokenDetails = new TokenDetails();
        when(authClient.obtainTokenDetailsByAuthorizationCode(code, redirectUrl)).thenReturn(tokenDetails);

        assertEquals(authClient.obtainTokenDetailsByAuthorizationCode(code, redirectUrl), tokenDetails);
    }

    @Test
    void getTokenByRefreshToken() {
        String refreshToken = "refresh-token1234";

        TokenDetails tokenDetails = new TokenDetails();
        when(authClient.obtainTokenDetailsByRefreshToken(refreshToken)).thenReturn(tokenDetails);

        assertEquals(authClient.obtainTokenDetailsByRefreshToken(refreshToken), tokenDetails);
    }

    @Test
    void obtainTokenByApplicationCredentials() {
        TokenDetails tokenDetails = new TokenDetails();
        when(authClient.obtainTokenDetailsByApplicationCredentials()).thenReturn(tokenDetails);

        assertEquals(authClient.obtainTokenDetailsByApplicationCredentials(), tokenDetails);
    }

    @Test
    void obtainTokenByRunOnBehalfOfUserCredentials() {
        TokenDetails tokenDetails = new TokenDetails();
        when(authClient.obtainTokenDetailsByRunOnBehalfOfUserCredentials("user1", "realm1")).thenReturn(tokenDetails);

        assertEquals(authClient.obtainTokenDetailsByRunOnBehalfOfUserCredentials("user1", "realm1"), tokenDetails);
    }

    @Test
    void parseAccessToken() throws Exception {
        JwtTokenGenerator tokenGenerator = new JwtTokenGenerator("http://localhost:8080/auth/test-realm",
                "producer-service", Arrays.asList("USER_READ", "USER_WRITE"));
        String accessToken = tokenGenerator.generateJwtAccessToken();
        String publicKey = KeyUtils.importPublicKeyToPem(tokenGenerator.getIdpPair().getPublic());

        when(publicKeyCacheService.getPublicKeyByRealm("test-realm")).thenReturn(publicKey.toString());
        when(oidcConfiguration.isCheckIsActive()).thenReturn(true);
        when(oidcConfiguration.isCheckTokenType()).thenReturn(true);

        authClient.parseAccessToken(accessToken, "test-realm");
    }

    @Test
    void parseAccessTokenPublicKeyIsOutdated() throws Exception {
        JwtTokenGenerator tokenGenerator = new JwtTokenGenerator("http://localhost:8080/auth/test-realm",
                "producer-service", Arrays.asList("USER_READ", "USER_WRITE"));
        String accessToken = tokenGenerator.generateJwtAccessToken();

        when(publicKeyCacheService.getPublicKeyByRealm("test-realm")).thenReturn("outdated key");

        String refreshedPublicKey = KeyUtils.importPublicKeyToPem(tokenGenerator.getIdpPair().getPublic());
        when(publicKeyCacheService.refreshPublicKey("test-realm")).thenReturn(refreshedPublicKey);

        when(oidcConfiguration.isCheckIsActive()).thenReturn(true);
        when(oidcConfiguration.isCheckTokenType()).thenReturn(true);

        authClient.parseAccessToken(accessToken, "test-realm");
    }

    @Test
    void obtainTokenDetailsByApplicationCredentials() {
        TokenDetails tokenDetails = new TokenDetails();
        when(authClient.obtainTokenDetailsByApplicationCredentials("user2", "password2", "realm2")).thenReturn(tokenDetails);

        assertEquals(authClient.obtainTokenDetailsByApplicationCredentials("user2", "password2", "realm2"), tokenDetails);
    }
}