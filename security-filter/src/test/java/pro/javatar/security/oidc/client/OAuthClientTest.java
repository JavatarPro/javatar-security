package pro.javatar.security.oidc.client;

import org.apache.http.message.BasicNameValuePair;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import pro.javatar.security.api.config.SecurityConfig;
import pro.javatar.security.oidc.exceptions.ExchangeTokenByCodeAuthenticationException;
import pro.javatar.security.oidc.exceptions.ObtainRefreshTokenException;
import pro.javatar.security.oidc.exceptions.ObtainTokenByUserCredentialAuthenticationException;
import pro.javatar.security.oidc.model.OAuth2Constants;
import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.services.OidcConfiguration;
import pro.javatar.security.oidc.services.api.RealmService;
import pro.javatar.security.oidc.utils.SpringTestConfig;

import java.util.*;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OAuthClientTest {

    @Spy
    @InjectMocks
    private OAuthClient client;

    @Mock
    private OidcConfiguration oidcConfiguration;

    @Captor
    private ArgumentCaptor<ArrayList<BasicNameValuePair>> paramsCaptor;
    private String code = UUID.randomUUID().toString();
    private String redirectUrl = "/some/redirect/url";
    String clientId = "user-management-service";
    String clientSecret = "86ff8f97-04b5-43f0-9c2f-6031d4e11aac";

    SecurityConfig config = new SpringTestConfig().securityConfig();

    @Mock
    RealmService realmService;

    @BeforeEach
    void setUp() {
        client.setConfig(config);
        client.setRealmService(realmService);
    }

    @Test
    void obtainTokenDetailsByAuthorizationCode() throws Exception {
        when(realmService.getRealmForCurrentRequest()).thenReturn("realm2");

        TokenDetails expectedTokenDetails = new TokenDetails();
        doReturn(expectedTokenDetails).when(client).obtainTokenDetails(eq("realm2"), paramsCaptor.capture());

        assertEquals(expectedTokenDetails, client.obtainTokenDetailsByAuthorizationCode(code, redirectUrl));

        Map<String, String> params = convertParamsToMap(paramsCaptor.getValue());
        assertThat(params.size(), is(5));
        assertThat(params.get(OAuth2Constants.GRANT_TYPE), is(OAuth2Constants.AUTHORIZATION_CODE));
        assertThat(params.get(OAuth2Constants.CODE), is(code));
        assertThat(params.get(OAuth2Constants.CLIENT_ID), is("user-management-service"));
        assertThat(params.get(OAuth2Constants.CLIENT_SECRET), is(clientSecret));
        assertThat(params.get(OAuth2Constants.REDIRECT_URI), is(redirectUrl));
    }

    @Test
    void obtainTokenDetailsByAuthorizationCodeException() throws Exception {
        when(realmService.getRealmForCurrentRequest()).thenReturn("realm2");

        doThrow(new RuntimeException()).when(client).obtainTokenDetails(any(), any());

        assertThrows(ExchangeTokenByCodeAuthenticationException.class, () -> client.obtainTokenDetailsByAuthorizationCode(code, redirectUrl));
    }

    @Test
    void obtainTokenDetailsByRefreshToken() throws Exception {
        String refreshToken = "refresh token";
        when(realmService.getRealmForCurrentRequest()).thenReturn("realm2");

        TokenDetails expectedTokenDetails = new TokenDetails();
        doReturn(expectedTokenDetails).when(client).obtainTokenDetails(eq("realm2"), paramsCaptor.capture());

        assertEquals(expectedTokenDetails, client.obtainTokenDetailsByRefreshToken(refreshToken));

        Map<String, String> params = convertParamsToMap(paramsCaptor.getValue());
        assertThat(params.size(), is(4));
        assertThat(params.get(OAuth2Constants.GRANT_TYPE), is(OAuth2Constants.REFRESH_TOKEN));
        assertThat(params.get(OAuth2Constants.REFRESH_TOKEN), is(refreshToken));
        assertThat(params.get(OAuth2Constants.CLIENT_ID), is(clientId));
        assertThat(params.get(OAuth2Constants.CLIENT_SECRET), is(clientSecret));
    }

    @Test
    void obtainTokenDetailsByRefreshTokenException() throws Exception {
        String refreshToken = "refresh token";
        when(realmService.getRealmForCurrentRequest()).thenReturn("realm2");

        doThrow(new RuntimeException()).when(client).obtainTokenDetails(any(), any());

        assertThrows(ObtainRefreshTokenException.class, () -> client.obtainTokenDetailsByRefreshToken(refreshToken));
    }

    @Test
    void obtainTokenDetailsByApplicationCredentialsByConfiguration() throws Exception {
        when(realmService.getRealmForCurrentRequest()).thenReturn("realm2");

        TokenDetails expectedTokenDetails = new TokenDetails();
        doReturn(expectedTokenDetails).when(client).obtainTokenDetails(eq("realm2"), paramsCaptor.capture());

        assertEquals(expectedTokenDetails, client.obtainTokenDetailsByApplicationCredentials());

        Map<String, String> params = convertParamsToMap(paramsCaptor.getValue());
        assertThat(params.size(), is(5));
        assertThat(params.get(OAuth2Constants.GRANT_TYPE), is(OAuth2Constants.PASSWORD));
        assertThat(params.get(OAuth2Constants.USERNAME), is("jenkins"));
        assertThat(params.get(OAuth2Constants.PASSWORD), is("se(ur3"));
        assertThat(params.get(OAuth2Constants.CLIENT_ID), is(clientId));
        assertThat(params.get(OAuth2Constants.CLIENT_SECRET), is(clientSecret));
    }

    @Test
    void obtainTokenDetailsByApplicationCredentialsByConfigurationException() throws Exception {
        when(realmService.getRealmForCurrentRequest()).thenReturn("realm2");

        doThrow(new RuntimeException()).when(client).obtainTokenDetails(any(), any());

        assertThrows(ObtainTokenByUserCredentialAuthenticationException.class, () -> client.obtainTokenDetailsByApplicationCredentials());
    }

    @Test
    void obtainTokenDetailsByRunOnBehalfOfUserCredentials() throws Exception {
        String username = "pupkin2";
        String userPassword = "pupkin2-password";
        String realm = "realm_sk";

        when(oidcConfiguration.getRunOnBehalfOfUserPassword(username, realm)).thenReturn(userPassword);

        TokenDetails expectedTokenDetails = new TokenDetails();
        doReturn(expectedTokenDetails).when(client).obtainTokenDetails(eq(realm), paramsCaptor.capture());

        assertEquals(expectedTokenDetails,
                client.obtainTokenDetailsByRunOnBehalfOfUserCredentials(username, realm));

        Map<String, String> params = convertParamsToMap(paramsCaptor.getValue());
        assertThat(params.size(), is(5));
        assertThat(params.get(OAuth2Constants.GRANT_TYPE), is(OAuth2Constants.PASSWORD));
        assertThat(params.get(OAuth2Constants.USERNAME), is(username));
        assertThat(params.get(OAuth2Constants.PASSWORD), is(userPassword));
        assertThat(params.get(OAuth2Constants.CLIENT_ID), is(clientId));
        assertThat(params.get(OAuth2Constants.CLIENT_SECRET), is(clientSecret));
    }

    @Test
    void obtainTokenDetailsByApplicationCredentialsWithParameters() throws Exception {
        String username = "pupkin3";
        String userPassword = "pupkin3-password";
        String realm = "some_realm";

        when(realmService.getRealmForCurrentRequest()).thenReturn(realm);

        TokenDetails expectedTokenDetails = new TokenDetails();
        doReturn(expectedTokenDetails).when(client).obtainTokenDetails(eq(realm), paramsCaptor.capture());

        assertEquals(expectedTokenDetails, client.obtainTokenDetailsByApplicationCredentials(username, userPassword));

        Map<String, String> params = convertParamsToMap(paramsCaptor.getValue());
        assertThat(params.size(), is(5));
        assertThat(params.get(OAuth2Constants.GRANT_TYPE), is(OAuth2Constants.PASSWORD));
        assertThat(params.get(OAuth2Constants.USERNAME), is(username));
        assertThat(params.get(OAuth2Constants.PASSWORD), is(userPassword));
        assertThat(params.get(OAuth2Constants.CLIENT_ID), is(clientId));
        assertThat(params.get(OAuth2Constants.CLIENT_SECRET), is(clientSecret));
    }

    @Test
    void prepareTokenEndpointUrl() {
        String realm = "test-realm";

        when(oidcConfiguration.getTokenEndpoint()).thenReturn("/{realm}/path");

        String tokenEndpointUrl = client.prepareTokenEndpointUrl(realm);
        assertThat(tokenEndpointUrl, is("http://195.201.110.123:48666/test-realm/path"));
    }

    private Map<String, String> convertParamsToMap(List<BasicNameValuePair> basicNameValuePairs) {
        Map<String, String> params = new HashMap<>();
        for (BasicNameValuePair basicNameValuePair : basicNameValuePairs) {
            params.put(basicNameValuePair.getName(), basicNameValuePair.getValue());
        }
        return params;
    }
}