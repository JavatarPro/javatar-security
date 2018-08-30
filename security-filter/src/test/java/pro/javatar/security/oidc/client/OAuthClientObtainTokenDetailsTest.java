package pro.javatar.security.oidc.client;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;

import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.exceptions.ExchangeTokenByCodeAuthenticationException;
import pro.javatar.security.oidc.services.OidcAuthenticationHelper;
import pro.javatar.security.oidc.services.OidcConfiguration;
import pro.javatar.security.oidc.utils.TestHelper;

import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import pro.javatar.security.oidc.utils.TestHelper;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@RunWith(PowerMockRunner.class)
@PrepareForTest({HttpClients.class, EntityUtils.class})
public class OAuthClientObtainTokenDetailsTest {

    @InjectMocks
    private OAuthClient client;
    @Mock
    private OidcConfiguration oidcConfiguration;
    @Mock
    private OidcAuthenticationHelper oidcAuthenticationHelper;
    @Mock
    private CloseableHttpClient httpClient;
    @Mock
    private CloseableHttpResponse httpResponse;
    @Mock
    private StatusLine statusLine;
    @Mock
    private HttpEntity httpEntity;
    @Captor
    private ArgumentCaptor<HttpPost> httpPostCaptor;

    @Test
    public void obtainTokenDetailsSuccessScenario() throws Exception {
        String realm = "realm-tenant";
        List<BasicNameValuePair> params = new ArrayList<>();

        PowerMockito.mockStatic(HttpClients.class);
        PowerMockito.mockStatic(EntityUtils.class);
        when(HttpClients.createDefault()).thenReturn(httpClient);

        when(oidcConfiguration.getIdentityProviderHost()).thenReturn("identity-provider.host");
        when(oidcConfiguration.getTokenEndpoint()).thenReturn("/{realm}/path");

        when(httpClient.execute(httpPostCaptor.capture())).thenReturn(httpResponse);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(HttpStatus.SC_OK);

        when(httpResponse.getEntity()).thenReturn(httpEntity);
        when(EntityUtils.toString(httpEntity)).thenReturn(TestHelper.getStub("obtain-token-success.json"));

        String accessToken = "access-token111";
        String refreshToken = "refresh-token222";
        when(oidcAuthenticationHelper.generateTokenDetails(accessToken, refreshToken))
                .thenReturn(new TokenDetails(accessToken, refreshToken, LocalDateTime.now()));

        TokenDetails tokenDetails = client.obtainTokenDetails(realm, params);

        assertThat(tokenDetails.getAccessToken(), is(accessToken));
        assertThat(tokenDetails.getRefreshToken(), is(refreshToken));
        assertThat(tokenDetails.getAccessExpiredIn(), is("900"));
        assertThat(tokenDetails.getRefreshExpiredIn(), is("1800"));

        HttpPost httpPost = httpPostCaptor.getValue();
        assertThat(httpPost.getURI().toString(), is("identity-provider.host/realm-tenant/path"));
        assertThat(httpPost.getAllHeaders().length, is(1));
        assertThat(httpPost.getAllHeaders()[0].getName(), is(HttpHeaders.CONTENT_TYPE));
        assertThat(httpPost.getAllHeaders()[0].getValue(), is(MediaType.APPLICATION_FORM_URLENCODED_VALUE));
    }

    @Test(expected = ExchangeTokenByCodeAuthenticationException.class)
    public void obtainTokenDetailsErrorScenario() throws Exception {
        String realm = "realm-tenant";
        List<BasicNameValuePair> params = new ArrayList<>();

        PowerMockito.mockStatic(HttpClients.class);
        PowerMockito.mockStatic(EntityUtils.class);
        when(HttpClients.createDefault()).thenReturn(httpClient);

        when(oidcConfiguration.getIdentityProviderHost()).thenReturn("identity-provider.host");
        when(oidcConfiguration.getTokenEndpoint()).thenReturn("/{realm}/path");

        when(httpClient.execute(httpPostCaptor.capture())).thenReturn(httpResponse);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(HttpStatus.SC_BAD_REQUEST);   //status not OK

        when(httpResponse.getEntity()).thenReturn(httpEntity);
        when(EntityUtils.toString(httpEntity)).thenReturn(TestHelper.getStub("obtain-token-error.json"));

        client.obtainTokenDetails(realm, params);
    }
}
