package pro.javatar.security.oidc.services;

import static junit.framework.TestCase.assertEquals;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import pro.javatar.security.oidc.client.OAuthClient;
import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.exceptions.ObtainRefreshTokenException;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.LocalDateTime;
import java.util.ArrayList;

public class UsersTokenServiceTest {

    private UsersTokenService service;
    private OidcAuthenticationHelper oidcAuthenticationHelper;
    private OAuthClient oAuthClient;
    private TokenDetails tokenDetails;

    @Before
    public void setUp() throws Exception {
        this.oidcAuthenticationHelper = mock(OidcAuthenticationHelper.class);
        this.oAuthClient = mock(OAuthClient.class);
        service = new UsersTokenService(oidcAuthenticationHelper, oAuthClient);

        tokenDetails = new TokenDetails("accessToken111", "refreshToken111", LocalDateTime.now());
    }

    @Test
    public void retrieveUsersTokenDetailsTokenIsExpired() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("login", tokenDetails, new ArrayList<>()));
        when(oidcAuthenticationHelper.isTokenExpiredOrShouldBeRefreshed(tokenDetails)).thenReturn(false);

        assertEquals(service.retrieveUsersTokenDetails(), tokenDetails);
    }

    @Test
    public void retrieveUsersTokenDetailsTokenIsNotExpired() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("login", tokenDetails, new ArrayList<>()));
        when(oidcAuthenticationHelper.isTokenExpiredOrShouldBeRefreshed(tokenDetails)).thenReturn(true);

        TokenDetails updatedTokenDetails = new TokenDetails();
        when(oAuthClient.obtainTokenDetailsByRefreshToken((tokenDetails.getRefreshToken())))
                .thenReturn(updatedTokenDetails);
        doNothing().when(oidcAuthenticationHelper).authenticateCurrentThread(updatedTokenDetails);

        assertEquals(service.retrieveUsersTokenDetails(), updatedTokenDetails);
    }

    @Test
    public void retrieveUsersTokenDetailsExceptionWhenTokenRefreshing() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("login", tokenDetails, new ArrayList<>()));
        when(oidcAuthenticationHelper.isTokenExpiredOrShouldBeRefreshed(tokenDetails)).thenReturn(true);

        when(oAuthClient.obtainTokenDetailsByRefreshToken(tokenDetails.getRefreshToken()))
                .thenThrow(new ObtainRefreshTokenException());

        assertEquals(service.retrieveUsersTokenDetails(), tokenDetails);
    }

    @Test
    public void retrieveUsersTokenDetailsWhenSecurityContextIsEmpty() throws Exception {
        SecurityContextHolder.clearContext();

        TokenDetails tokenDetails = service.retrieveUsersTokenDetails();
        assertThat(tokenDetails.isEmpty(), is(true));

    }
}