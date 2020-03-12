package pro.javatar.security.oidc.services;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pro.javatar.security.api.config.SecurityConfig;
import pro.javatar.security.oidc.client.OAuthClient;
import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.services.api.RealmService;
import pro.javatar.security.oidc.utils.JwtTokenGenerator;
import pro.javatar.security.oidc.utils.KeyUtils;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import pro.javatar.security.oidc.utils.SpringTestConfig;

import java.util.Arrays;
import java.util.Collection;

class AuthenticationServiceTest {

    private static final String CLIENT_ID = "producer-service";

    private TokenService tokenService;

    private OidcAuthenticationHelper oidcAuthenticationHelper;

    private PublicKeyCacheService publicKeyCacheService;

    private AuthenticationService service;

    private SecurityConfig securityConfig;

    @BeforeEach
    void setUp() {
        tokenService = mock(TokenService.class);
        publicKeyCacheService = mock(PublicKeyCacheService.class);

        OidcConfiguration oidcConfiguration = new OidcConfiguration();

        securityConfig = new SpringTestConfig().getSecurityConfigMock(CLIENT_ID);

        RealmService realmService = mock(RealmService.class);
        OAuthClient oAuthClient = new OAuthClient(oidcConfiguration, realmService, publicKeyCacheService, securityConfig);

        oidcAuthenticationHelper = new OidcAuthenticationHelper();
        oidcAuthenticationHelper.setOidcConfiguration(oidcConfiguration);
        oidcAuthenticationHelper.setOAuthClient(oAuthClient);
        oidcAuthenticationHelper.setConfig(securityConfig);

        service = new AuthenticationService(this.tokenService, oidcAuthenticationHelper);
    }

    @Test
    void authenticateByTokenDetails() throws Exception {
        JwtTokenGenerator tokenGenerator =
                new JwtTokenGenerator("http://localhost:8080/auth/test-realm",
                        CLIENT_ID, Arrays.asList("USER_READ", "USER_WRITE"));
        String accessToken = tokenGenerator.generateJwtAccessToken();
        TokenDetails tokenDetails = new TokenDetails();
        tokenDetails.setAccessToken(accessToken);

        String publicKey = KeyUtils.importPublicKeyToPem(tokenGenerator.getIdpPair().getPublic());
        when(publicKeyCacheService.getPublicKeyByRealm("test-realm")).thenReturn(publicKey);

        service.authenticateByTokenDetails(tokenDetails);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        TokenDetails credentials = (TokenDetails) authentication.getCredentials();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        assertThat(credentials.getAccessToken(), is(accessToken)) ;

        assertThat(authorities.size(), is(2));
        assertThat(authorities.contains(new SimpleGrantedAuthority("USER_READ")), is(true));
        assertThat(authorities.contains(new SimpleGrantedAuthority("USER_WRITE")), is(true));
    }

    @Test
    void authenticateByRefreshToken() throws Exception {
        JwtTokenGenerator tokenGenerator =
                new JwtTokenGenerator("http://localhost:8080/auth/test-realm",
                        CLIENT_ID, Arrays.asList("USER_READ", "USER_WRITE"));
        String accessToken = tokenGenerator.generateJwtAccessToken();
        TokenDetails tokenDetails = new TokenDetails();
        tokenDetails.setAccessToken(accessToken);
        String refreshToken = "refresh-token";

        when(tokenService.getTokenByRefreshToken(refreshToken)).thenReturn(tokenDetails);

        String publicKey = KeyUtils.importPublicKeyToPem(tokenGenerator.getIdpPair().getPublic());
        when(publicKeyCacheService.getPublicKeyByRealm("test-realm")).thenReturn(publicKey);

        service.authenticateByRefreshToken(refreshToken);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        TokenDetails credentials = (TokenDetails) authentication.getCredentials();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        assertThat(credentials.getAccessToken(), is(accessToken)) ;

        assertThat(authorities.size(), is(2));
        assertThat(authorities.contains(new SimpleGrantedAuthority("USER_READ")), is(true));
        assertThat(authorities.contains(new SimpleGrantedAuthority("USER_WRITE")), is(true));
    }
}