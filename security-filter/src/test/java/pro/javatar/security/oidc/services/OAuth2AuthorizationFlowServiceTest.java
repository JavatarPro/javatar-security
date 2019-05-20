package pro.javatar.security.oidc.services;

import static junit.framework.TestCase.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import pro.javatar.security.api.config.SecurityConfig;
import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.client.OAuthClient;
import pro.javatar.security.oidc.utils.JwtTokenGenerator;
import pro.javatar.security.oidc.utils.KeyUtils;

import org.junit.Before;
import org.junit.Test;
import pro.javatar.security.oidc.utils.SpringTestConfig;

import java.util.Arrays;
import java.util.UUID;

public class OAuth2AuthorizationFlowServiceTest {

    private OAuth2AuthorizationFlowService service;
    private OAuthClient authClient;
    private OidcConfiguration oidcConfiguration;
    private PublicKeyCacheService publicKeyCacheService;
    private SecurityConfig securityConfig;

    @Before
    public void setUp() throws Exception {
        securityConfig = new SpringTestConfig().securityConfig();

        authClient = mock(OAuthClient.class);
        oidcConfiguration = mock(OidcConfiguration.class);
        publicKeyCacheService = mock(PublicKeyCacheService.class);

        service = new OAuth2AuthorizationFlowService(authClient, publicKeyCacheService, securityConfig);
    }

    @Test
    public void getTokenDetailsByCode() throws Exception {
        String code = UUID.randomUUID().toString();
        String redirectUrl = "context/test";

        TokenDetails tokenDetails = new TokenDetails();
        when(authClient.obtainTokenDetailsByAuthorizationCode(code, redirectUrl)).thenReturn(tokenDetails);

        assertEquals(service.getTokenDetailsByCode(code, redirectUrl), tokenDetails);
    }

    @Test
    public void getTokenByRefreshToken() throws Exception {
        String refreshToken = "refresh-token1234";

        TokenDetails tokenDetails = new TokenDetails();
        when(authClient.obtainTokenDetailsByRefreshToken(refreshToken)).thenReturn(tokenDetails);

        assertEquals(service.getTokenByRefreshToken(refreshToken), tokenDetails);
    }

    @Test
    public void obtainTokenByApplicationCredentials() throws Exception {
        TokenDetails tokenDetails = new TokenDetails();
        when(authClient.obtainTokenDetailsByApplicationCredentials()).thenReturn(tokenDetails);

        assertEquals(service.obtainTokenByApplicationCredentials(), tokenDetails);
    }

    @Test
    public void obtainTokenByRunOnBehalfOfUserCredentials() throws Exception {
        TokenDetails tokenDetails = new TokenDetails();
        when(authClient.obtainTokenDetailsByRunOnBehalfOfUserCredentials("user1", "realm1")).thenReturn(tokenDetails);

        assertEquals(service.obtainTokenByRunOnBehalfOfUserCredentials("user1", "realm1"), tokenDetails);
    }

    @Test
    public void parseAccessToken() throws Exception {
        JwtTokenGenerator tokenGenerator = new JwtTokenGenerator("http://localhost:8080/auth/test-realm",
                "producer-service", Arrays.asList("USER_READ", "USER_WRITE"));
        String accessToken = tokenGenerator.generateJwtAccessToken();
        String publicKey = KeyUtils.importPublicKeyToPem(tokenGenerator.getIdpPair().getPublic());

        when(publicKeyCacheService.getPublicKeyByRealm("test-realm")).thenReturn(publicKey.toString());
        when(oidcConfiguration.isCheckIsActive()).thenReturn(true);
        when(oidcConfiguration.isCheckTokenType()).thenReturn(true);

        service.parseAccessToken(accessToken, "test-realm");
    }

    @Test
    public void parseAccessTokenPublicKeyIsOutdated() throws Exception {
        JwtTokenGenerator tokenGenerator = new JwtTokenGenerator("http://localhost:8080/auth/test-realm",
                "producer-service", Arrays.asList("USER_READ", "USER_WRITE"));
        String accessToken = tokenGenerator.generateJwtAccessToken();

        when(publicKeyCacheService.getPublicKeyByRealm("test-realm")).thenReturn("outdated public key");

        String refreshedPublicKey = KeyUtils.importPublicKeyToPem(tokenGenerator.getIdpPair().getPublic());
        when(publicKeyCacheService.refreshPublicKey("test-realm")).thenReturn(refreshedPublicKey);

        when(oidcConfiguration.isCheckIsActive()).thenReturn(true);
        when(oidcConfiguration.isCheckTokenType()).thenReturn(true);

        service.parseAccessToken(accessToken, "test-realm");
    }

    @Test
    public void obtainTokenDetailsByApplicationCredentials() throws Exception {
        TokenDetails tokenDetails = new TokenDetails();
        when(authClient.obtainTokenDetailsByApplicationCredentials("user2", "password2", "realm2")).thenReturn(tokenDetails);

        assertEquals(service.obtainTokenDetailsByApplicationCredentials("user2", "password2", "realm2"), tokenDetails);
    }
}