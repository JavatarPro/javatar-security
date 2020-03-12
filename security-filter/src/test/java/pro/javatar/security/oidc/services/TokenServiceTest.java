package pro.javatar.security.oidc.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pro.javatar.security.oidc.client.OAuthClient;
import pro.javatar.security.oidc.exceptions.ObtainRefreshTokenException;
import pro.javatar.security.oidc.model.TokenDetails;

import java.time.LocalDateTime;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TokenServiceTest {

    private TokenService service;
    private UsersTokenService usersTokenService;
    private ApplicationTokenService applicationTokenService;
    private OAuthClient oAuthClient;

    @BeforeEach
    void setUp() {
        usersTokenService = mock(UsersTokenService.class);
        applicationTokenService = mock(ApplicationTokenService.class);
        oAuthClient = mock(OAuthClient.class);
        service = new TokenService(usersTokenService, applicationTokenService, oAuthClient);
    }

    @Test
    void getApplicationTokenDetails() {
        TokenDetails tokenDetails = new TokenDetails();
        when(usersTokenService.retrieveUsersTokenDetails()).thenReturn(tokenDetails);
        TokenDetails applicationTokenDetails =
                new TokenDetails("accessToken444", "refreshToken4", LocalDateTime.now());
        when(applicationTokenService.getApplicationTokenDetails()).thenReturn(applicationTokenDetails);

        assertEquals(service.getTokenDetails(), applicationTokenDetails);
    }

    @Test
    void getUserTokenDetails() {
        TokenDetails userTokenDetails =
                new TokenDetails("accessToken5", "refreshToken555", LocalDateTime.now());
        when(usersTokenService.retrieveUsersTokenDetails()).thenReturn(userTokenDetails);

        assertEquals(service.getTokenDetails(), userTokenDetails);
    }

    @Test
    void getTokenByRefreshToken() {
        String refreshToken = "refresh-token333";
        TokenDetails tokenDetails = new TokenDetails();
        when(oAuthClient.obtainTokenDetailsByRefreshToken(refreshToken)).thenReturn(tokenDetails);

        assertSame(service.getTokenByRefreshToken(refreshToken), tokenDetails);
    }

    @Test
    void getTokenByRefreshTokenException() {
        String refreshToken = "refresh-token333";
        when(oAuthClient.obtainTokenDetailsByRefreshToken(refreshToken))
                .thenThrow(new ObtainRefreshTokenException());

        assertThrows(ObtainRefreshTokenException.class, () -> service.getTokenByRefreshToken(refreshToken));
    }
}