package pro.javatar.security.oidc.client;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

import pro.javatar.security.oidc.model.OAuth2Constants;
import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.exceptions.ExchangeTokenByCodeAuthenticationException;
import pro.javatar.security.oidc.exceptions.ObtainRefreshTokenException;
import pro.javatar.security.oidc.exceptions.ObtainTokenByUserCredentialAuthenticationException;
import pro.javatar.security.oidc.services.OidcAuthenticationHelper;
import pro.javatar.security.oidc.services.OidcConfiguration;

import org.apache.http.message.BasicNameValuePair;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.powermock.core.classloader.annotations.PrepareForTest;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RunWith(MockitoJUnitRunner.class)
@PrepareForTest(OAuthClient.class)
public class OAuthClientTest {

    @Spy
    @InjectMocks
    private OAuthClient client;
    @Mock
    private OidcConfiguration oidcConfiguration;
    @Mock
    private OidcAuthenticationHelper oidcAuthenticationHelper;
    @Captor
    private ArgumentCaptor<ArrayList<BasicNameValuePair>> paramsCaptor;
    private String code = UUID.randomUUID().toString();
    private String redirectUrl = "/some/redirect/url";
    private String clientSecret = UUID.randomUUID().toString();

    @Test
    public void obtainTokenDetailsByAuthorizationCode() throws Exception {
        when(oidcConfiguration.getClientId()).thenReturn("user-service");
        when(oidcConfiguration.getClientSecret()).thenReturn(clientSecret);

        when(oidcAuthenticationHelper.getRealmForCurrentRequest()).thenReturn("realm2");

        TokenDetails expectedTokenDetails = new TokenDetails();
        doReturn(expectedTokenDetails).when(client).obtainTokenDetails(eq("realm2"), paramsCaptor.capture());

        assertEquals(expectedTokenDetails, client.obtainTokenDetailsByAuthorizationCode(code, redirectUrl));

        Map<String, String> params = convertParamsToMap(paramsCaptor.getValue());
        assertThat(params.size(), is(5));
        assertThat(params.get(OAuth2Constants.GRANT_TYPE), is(OAuth2Constants.AUTHORIZATION_CODE));
        assertThat(params.get(OAuth2Constants.CODE), is(code));
        assertThat(params.get(OAuth2Constants.CLIENT_ID), is("user-service"));
        assertThat(params.get(OAuth2Constants.CLIENT_SECRET), is(clientSecret));
        assertThat(params.get(OAuth2Constants.REDIRECT_URI), is(redirectUrl));
    }

    @Test(expected = ExchangeTokenByCodeAuthenticationException.class)
    public void obtainTokenDetailsByAuthorizationCodeException() throws Exception {
        when(oidcConfiguration.getClientId()).thenReturn("user-service");
        when(oidcConfiguration.getClientSecret()).thenReturn(clientSecret);

        when(oidcAuthenticationHelper.getRealmForCurrentRequest()).thenReturn("realm2");

        doThrow(new RuntimeException()).when(client).obtainTokenDetails(any(), any());

        client.obtainTokenDetailsByAuthorizationCode(code, redirectUrl);
    }

    @Test
    public void obtainTokenDetailsByRefreshToken() throws Exception {
        String refreshToken = "refresh token";
        when(oidcConfiguration.getClientId()).thenReturn("producer-service");
        when(oidcConfiguration.getClientSecret()).thenReturn(clientSecret);

        when(oidcAuthenticationHelper.getRealmForCurrentRequest()).thenReturn("realm2");

        TokenDetails expectedTokenDetails = new TokenDetails();
        doReturn(expectedTokenDetails).when(client).obtainTokenDetails(eq("realm2"), paramsCaptor.capture());

        assertEquals(expectedTokenDetails, client.obtainTokenDetailsByRefreshToken(refreshToken));

        Map<String, String> params = convertParamsToMap(paramsCaptor.getValue());
        assertThat(params.size(), is(4));
        assertThat(params.get(OAuth2Constants.GRANT_TYPE), is(OAuth2Constants.REFRESH_TOKEN));
        assertThat(params.get(OAuth2Constants.REFRESH_TOKEN), is(refreshToken));
        assertThat(params.get(OAuth2Constants.CLIENT_ID), is("producer-service"));
        assertThat(params.get(OAuth2Constants.CLIENT_SECRET), is(clientSecret));
    }

    @Test(expected = ObtainRefreshTokenException.class)
    public void obtainTokenDetailsByRefreshTokenException() throws Exception {
        String refreshToken = "refresh token";
        when(oidcConfiguration.getClientId()).thenReturn("producer-service");
        when(oidcConfiguration.getClientSecret()).thenReturn(clientSecret);

        when(oidcAuthenticationHelper.getRealmForCurrentRequest()).thenReturn("realm2");

        doThrow(new RuntimeException()).when(client).obtainTokenDetails(any(), any());

        client.obtainTokenDetailsByRefreshToken(refreshToken);
    }

    @Test
    public void obtainTokenDetailsByApplicationCredentialsByConfiguration() throws Exception {
        when(oidcConfiguration.getUsername()).thenReturn("pupkin1");
        when(oidcConfiguration.getUserPassword()).thenReturn("pupkin1-password");

        when(oidcAuthenticationHelper.getRealmForCurrentRequest()).thenReturn("realm2");

        when(oidcConfiguration.getClientId()).thenReturn("consumer-service");
        when(oidcConfiguration.getClientSecret()).thenReturn(clientSecret);

        TokenDetails expectedTokenDetails = new TokenDetails();
        doReturn(expectedTokenDetails).when(client).obtainTokenDetails(eq("realm2"), paramsCaptor.capture());

        assertEquals(expectedTokenDetails, client.obtainTokenDetailsByApplicationCredentials());

        Map<String, String> params = convertParamsToMap(paramsCaptor.getValue());
        assertThat(params.size(), is(5));
        assertThat(params.get(OAuth2Constants.GRANT_TYPE), is(OAuth2Constants.PASSWORD));
        assertThat(params.get(OAuth2Constants.USERNAME), is("pupkin1"));
        assertThat(params.get(OAuth2Constants.PASSWORD), is("pupkin1-password"));
        assertThat(params.get(OAuth2Constants.CLIENT_ID), is("consumer-service"));
        assertThat(params.get(OAuth2Constants.CLIENT_SECRET), is(clientSecret));
    }

    @Test(expected = ObtainTokenByUserCredentialAuthenticationException.class)
    public void obtainTokenDetailsByApplicationCredentialsByConfigurationException() throws Exception {
        when(oidcConfiguration.getUsername()).thenReturn("pupkin1");
        when(oidcConfiguration.getUserPassword()).thenReturn("pupkin1-password");

        when(oidcAuthenticationHelper.getRealmForCurrentRequest()).thenReturn("realm2");

        when(oidcConfiguration.getClientId()).thenReturn("consumer-service");
        when(oidcConfiguration.getClientSecret()).thenReturn(clientSecret);

        doThrow(new RuntimeException()).when(client).obtainTokenDetails(any(), any());

        client.obtainTokenDetailsByApplicationCredentials();
    }

    @Test
    public void obtainTokenDetailsByRunOnBehalfOfUserCredentials() throws Exception {
        String username = "pupkin2";
        String userPassword = "pupkin2-password";
        String realm = "realm_sk";

        when(oidcConfiguration.getRunOnBehalfOfUserPassword(username, realm)).thenReturn(userPassword);

        when(oidcConfiguration.getClientId()).thenReturn("work-service");
        when(oidcConfiguration.getClientSecret()).thenReturn(clientSecret);

        TokenDetails expectedTokenDetails = new TokenDetails();
        doReturn(expectedTokenDetails).when(client).obtainTokenDetails(eq(realm), paramsCaptor.capture());

        assertEquals(expectedTokenDetails,
                client.obtainTokenDetailsByRunOnBehalfOfUserCredentials(username, realm));

        Map<String, String> params = convertParamsToMap(paramsCaptor.getValue());
        assertThat(params.size(), is(5));
        assertThat(params.get(OAuth2Constants.GRANT_TYPE), is(OAuth2Constants.PASSWORD));
        assertThat(params.get(OAuth2Constants.USERNAME), is(username));
        assertThat(params.get(OAuth2Constants.PASSWORD), is(userPassword));
        assertThat(params.get(OAuth2Constants.CLIENT_ID), is("work-service"));
        assertThat(params.get(OAuth2Constants.CLIENT_SECRET), is(clientSecret));
    }

    @Test
    public void obtainTokenDetailsByApplicationCredentialsWithParameters() throws Exception {
        String username = "pupkin3";
        String userPassword = "pupkin3-password";
        String realm = "some_realm";

        when(oidcAuthenticationHelper.getRealmForCurrentRequest()).thenReturn(realm);

        when(oidcConfiguration.getClientId()).thenReturn("work-service");
        when(oidcConfiguration.getClientSecret()).thenReturn(clientSecret);

        TokenDetails expectedTokenDetails = new TokenDetails();
        doReturn(expectedTokenDetails).when(client).obtainTokenDetails(eq(realm), paramsCaptor.capture());

        assertEquals(expectedTokenDetails, client.obtainTokenDetailsByApplicationCredentials(username, userPassword));

        Map<String, String> params = convertParamsToMap(paramsCaptor.getValue());
        assertThat(params.size(), is(5));
        assertThat(params.get(OAuth2Constants.GRANT_TYPE), is(OAuth2Constants.PASSWORD));
        assertThat(params.get(OAuth2Constants.USERNAME), is(username));
        assertThat(params.get(OAuth2Constants.PASSWORD), is(userPassword));
        assertThat(params.get(OAuth2Constants.CLIENT_ID), is("work-service"));
        assertThat(params.get(OAuth2Constants.CLIENT_SECRET), is(clientSecret));
    }

    @Test
    public void prepareTokenEndpointUrl() throws Exception {
        String realm = "test-realm";

        when(oidcConfiguration.getIdentityProviderHost()).thenReturn("identity-provider.host");
        when(oidcConfiguration.getTokenEndpoint()).thenReturn("/{realm}/path");

        String tokenEndpointUrl = client.prepareTokenEndpointUrl(realm);
        assertThat(tokenEndpointUrl, is("identity-provider.host/test-realm/path"));
    }

    private Map<String, String> convertParamsToMap(List<BasicNameValuePair> basicNameValuePairs) {
        Map<String, String> params = new HashMap<>();
        for (BasicNameValuePair basicNameValuePair : basicNameValuePairs) {
            params.put(basicNameValuePair.getName(), basicNameValuePair.getValue());
        }
        return params;
    }
}