package pro.javatar.security.oidc.services;

import static junit.framework.TestCase.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import pro.javatar.security.oidc.client.OAuthClient;
import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.model.UserKey;

import org.junit.Before;
import org.junit.Test;

public class ApplicationTokenServiceTest {

    private OAuthClient oAuthClient;
    private OidcAuthenticationHelper oidcAuthenticationHelper;
    private OnBehalfOfUsernameHolder onBehalfOfUsernameHolder;
    private ApplicationTokenHolder applicationTokenHolder;
    private OidcConfiguration oidcConfiguration;
    private ApplicationTokenService service;

    @Before
    public void setUp() throws Exception {
        oAuthClient = mock(OAuthClient.class);
        oidcAuthenticationHelper = mock(OidcAuthenticationHelper.class);
        oidcConfiguration = new OidcConfiguration();
        onBehalfOfUsernameHolder = new OnBehalfOfUsernameHolder();
        applicationTokenHolder = new ApplicationTokenHolder();

        service = new ApplicationTokenService(oAuthClient, oidcAuthenticationHelper,
                        onBehalfOfUsernameHolder, applicationTokenHolder, oidcConfiguration);
    }

    @Test
    public void getApplicationTokenDetails() throws Exception {
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
    public void getApplicationTokenDetailsAccessTokenIsNotExpired() throws Exception {
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
    public void getApplicationTokenDetailsAccessTokenIsExpired() throws Exception {
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