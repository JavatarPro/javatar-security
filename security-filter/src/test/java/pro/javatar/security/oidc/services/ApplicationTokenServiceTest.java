package pro.javatar.security.oidc.services;

import static junit.framework.TestCase.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pro.javatar.security.oidc.client.OAuthClient;
import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.model.UserKey;

class ApplicationTokenServiceTest {

    private OAuthClient oAuthClient;
    private OidcAuthenticationHelper oidcAuthenticationHelper;
    private OnBehalfOfUsernameHolder onBehalfOfUsernameHolder;
    private ApplicationTokenHolder applicationTokenHolder;
    private ApplicationTokenService service;

    @BeforeEach
    void setUp() {
        oAuthClient = mock(OAuthClient.class);
        oidcAuthenticationHelper = mock(OidcAuthenticationHelper.class);
        OidcConfiguration oidcConfiguration = new OidcConfiguration();
        onBehalfOfUsernameHolder = new OnBehalfOfUsernameHolder();
        applicationTokenHolder = new ApplicationTokenHolder();

        service = new ApplicationTokenService(oAuthClient, oidcAuthenticationHelper,
                                              onBehalfOfUsernameHolder, applicationTokenHolder, oidcConfiguration);
    }

    @Test
    void getApplicationTokenDetails() {
        onBehalfOfUsernameHolder.removeUser();
        UserKey userKey1 = new UserKey("user1", "realm1");
        onBehalfOfUsernameHolder.putUser(userKey1);

        TokenDetails tokenDetails = new TokenDetails();
        applicationTokenHolder.setTokenDetails(userKey1, tokenDetails);
        when(oAuthClient.obtainTokenDetailsByRunOnBehalfOfUserCredentials(
                userKey1.getLogin(), userKey1.getRealm()))
                .thenReturn(tokenDetails);

        TokenDetails applicationTokenDetails = service.getApplicationTokenDetails();
        assertEquals(applicationTokenDetails, tokenDetails);
    }

    @Test
    void getApplicationTokenDetailsAccessTokenIsNotExpired() {
        onBehalfOfUsernameHolder.removeUser();
        UserKey userKey1 = new UserKey("user1", "realm1");
        onBehalfOfUsernameHolder.putUser(userKey1);

        TokenDetails tokenDetails = new TokenDetails();
        tokenDetails.setAccessToken("access-token3242");
        applicationTokenHolder.setTokenDetails(userKey1, tokenDetails);
        when(oidcAuthenticationHelper.isTokenExpiredOrShouldBeRefreshed(tokenDetails)).thenReturn(false);

        TokenDetails applicationTokenDetails = service.getApplicationTokenDetails();
        assertEquals(applicationTokenDetails, tokenDetails);
    }

    @Test
    void getApplicationTokenDetailsAccessTokenIsExpired() {
        onBehalfOfUsernameHolder.removeUser();
        UserKey userKey1 = new UserKey("user1", "realm1");
        onBehalfOfUsernameHolder.putUser(userKey1);

        TokenDetails tokenDetails = new TokenDetails();
        tokenDetails.setAccessToken("access-token123");
        tokenDetails.setRefreshToken("refresh-token123");
        applicationTokenHolder.setTokenDetails(userKey1, tokenDetails);
        when(oAuthClient.obtainTokenDetailsByRunOnBehalfOfUserCredentials(
                userKey1.getLogin(), userKey1.getRealm()))
                .thenReturn(tokenDetails);
        when(oidcAuthenticationHelper.isTokenExpiredOrShouldBeRefreshed(tokenDetails)).thenReturn(true);

        TokenDetails refreshedTokenDetails = new TokenDetails();
        when(oAuthClient.obtainTokenDetailsByRefreshToken(tokenDetails.getRefreshToken()))
                .thenReturn(refreshedTokenDetails);

        TokenDetails applicationTokenDetails = service.getApplicationTokenDetails();
        assertEquals(applicationTokenDetails, refreshedTokenDetails);
    }
}