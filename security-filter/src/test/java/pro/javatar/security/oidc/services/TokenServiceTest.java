package pro.javatar.security.oidc.services;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.exceptions.ObtainRefreshTokenException;

import org.junit.Before;
import org.junit.Test;

import java.time.LocalDateTime;

public class TokenServiceTest {

    private TokenService service;
    private UsersTokenService usersTokenService;
    private ApplicationTokenService applicationTokenService;
    private OAuth2AuthorizationFlowService auth2AuthorizationFlowService;

    @Before
    public void setUp() throws Exception {
        usersTokenService = mock(UsersTokenService.class);
        applicationTokenService = mock(ApplicationTokenService.class);
        auth2AuthorizationFlowService = mock(OAuth2AuthorizationFlowService.class);
        service =
                new TokenService(usersTokenService, applicationTokenService, auth2AuthorizationFlowService);
    }

    @Test
    public void getApplicationTokenDetails() throws Exception {
        TokenDetails tokenDetails = new TokenDetails();
        when(usersTokenService.retrieveUsersTokenDetails()).thenReturn(tokenDetails);
        TokenDetails applicationTokenDetails =
                new TokenDetails("accessToken444", "refreshToken4", LocalDateTime.now());
        when(applicationTokenService.getApplicationTokenDetails()).thenReturn(applicationTokenDetails);

        assertEquals(service.getTokenDetails(), applicationTokenDetails);
    }

    @Test
    public void getUserTokenDetails() throws Exception {
        TokenDetails userTokenDetails =
                new TokenDetails("accessToken5", "refreshToken555", LocalDateTime.now());
        when(usersTokenService.retrieveUsersTokenDetails()).thenReturn(userTokenDetails);

        assertEquals(service.getTokenDetails(), userTokenDetails);
    }

    @Test
    public void getTokenByRefreshToken() throws Exception {
        String refreshToken = "refresh-token333";
        TokenDetails tokenDetails = new TokenDetails();
        when(auth2AuthorizationFlowService.getTokenByRefreshToken(refreshToken)).thenReturn(tokenDetails);

        assertSame(service.getTokenByRefreshToken(refreshToken), tokenDetails);
    }

    @Test(expected = ObtainRefreshTokenException.class)
    public void getTokenByRefreshTokenException() throws Exception {
        String refreshToken = "refresh-token333";
        when(auth2AuthorizationFlowService.getTokenByRefreshToken(refreshToken))
                .thenThrow(new ObtainRefreshTokenException());

        service.getTokenByRefreshToken(refreshToken);
    }
}