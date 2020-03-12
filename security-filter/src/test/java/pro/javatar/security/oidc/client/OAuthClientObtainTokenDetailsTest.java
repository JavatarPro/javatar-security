package pro.javatar.security.oidc.client;

import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.BasicHttpEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import pro.javatar.security.api.config.SecurityConfig;
import pro.javatar.security.oidc.exceptions.ExchangeTokenByCodeAuthenticationException;
import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.services.OidcAuthenticationHelper;
import pro.javatar.security.oidc.services.OidcConfiguration;
import pro.javatar.security.oidc.services.PublicKeyCacheService;
import pro.javatar.security.oidc.services.api.RealmService;
import pro.javatar.security.oidc.services.impl.RealmServiceImpl;
import pro.javatar.security.oidc.utils.SpringTestConfig;
import pro.javatar.security.oidc.utils.TestHelper;

import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith({SpringExtension.class})
public class OAuthClientObtainTokenDetailsTest {

    public static final String REALM = "javatar-security";

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
    @Mock
    PublicKeyCacheService publicKeyCacheService;
    @Captor
    private ArgumentCaptor<HttpPost> httpPostCaptor;

    @BeforeEach
    void setUp() {
        SecurityConfig config = new SpringTestConfig().securityConfig();
        RealmService realmService = new RealmServiceImpl(config);
        client = new OAuthClient(oidcConfiguration, realmService, publicKeyCacheService, config){
            @Override
            CloseableHttpClient createDefaultHttpClient() {
                return httpClient;
            }
        };

        when(publicKeyCacheService.getPublicKeyByRealm(REALM)).thenReturn("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0zu4hSUMSsAMQIO/5cun3XPDvHeKmpYuZb5ylzP0JGsvwQIKzf232LAkdOjn8brUtLxLE7R2zramGH+EYiObuKloaGAxgUTyu0wfi2BbZ5junaE56ge69UrGPTePQ0K6w3nWItOFerjEOi0k4kcSAbMof3tot4bp9J5CG/7eFGMBPY1Ru2DdTC8dN9Ipbq6EbvbM5n1mOOz+UkGuFvCozFhJv3wrLVvgOCC4TelZXFClJRzQUddC67GYufmlbd5G6K6qxPwI6ztvZEwGGKp94MukoWsR19xeUdKud2W4GUvHicnNwwIwSOxeIgNqPrXXsFKzSY8TT8mrs1hZRgIPsQIDAQAB");
    }

    @Test
    void obtainTokenDetailsSuccessScenario() throws Exception {
        List<BasicNameValuePair> params = new ArrayList<>();

        when(oidcConfiguration.getTokenEndpoint()).thenReturn("/{realm}/path");

        when(httpClient.execute(httpPostCaptor.capture())).thenReturn(httpResponse);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(HttpStatus.SC_OK);

        BasicHttpEntity httpEntity = new BasicHttpEntity();
        httpEntity.setContent(TestHelper.getStubAsInputStream("stub/identity-provider-response-stub.json"));
        when(httpResponse.getEntity()).thenReturn(httpEntity);

        String accessToken = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ2S0RkVV83VXNqeFFWSWJIZ1E3aGZvS2EtRDBuQWs5MFFYejI4dm0zYnRjIn0.eyJqdGkiOiI4ZmIwYjQ5Ny01ZjQzLTQ5NTQtOGU2OC0xYjcxNmRmY2NmZjIiLCJleHAiOjE1NTg5MDM4NjMsIm5iZiI6MCwiaWF0IjoxNTU4OTAzNTYzLCJpc3MiOiJodHRwOi8vMTk1LjIwMS4xMTAuMTIzOjQ4NjY2L2F1dGgvcmVhbG1zL2phdmF0YXItc2VjdXJpdHkiLCJhdWQiOiJpbnRlcnZpZXctc2VydmljZSIsInN1YiI6IjhkNjAwOWIwLTViZDgtNDUzMy05Y2ZhLTBjZTU1NWUyYjIyOCIsInR5cCI6IkJlYXJlciIsImF6cCI6ImludGVydmlldy1zZXJ2aWNlIiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiY2IyM2Q5YjktODY4OC00N2M1LWJlYzAtNzRmNjIzM2RkYWZkIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6W10sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJCb3J5cyBab3JhIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYm9yeXMiLCJnaXZlbl9uYW1lIjoiQm9yeXMiLCJmYW1pbHlfbmFtZSI6IlpvcmEiLCJlbWFpbCI6ImJvcnlzLnpvcmFAamF2YXRhci5wcm8ifQ.0J7oVpCdu4AL6Y32SLW5tHZ7_JvfJSusGf5bKknTT-brlhRrjzsoxL0P1J2AJtTZREz5uW54DrBZAZuxkG_g2MpZnWYRa8gmvcc_CJJee3VOrFG6QueuI__ovxIvICgRH7W_aBykX3ccj16DhkEarxLHrjHDEMrgPsUIJcScSGoUHo0Cj0xPOr-txslUaM5UXNdf-EhGUahOUynpL1euItyEU_41QfqgYnCfhA3p_FrZOPJmo54JdoYWxTTU4rDOcCbgBv90BjLZ7vEaoMKL4WKMoy_tNMB4eWqX5eG8DywyRFPSjOaGoVpI5KUHQZi5RPq6IS-_5DTZ8SscV9spLg";
        String refreshToken = "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI4ZjVjMDMxZS00YTM3LTRhZGEtOGMxMy0xYjFhODkxODhlYjYifQ.eyJqdGkiOiJjYTRkNzNmNi0yZTcxLTRiYWYtOTFjYy1iYmM3ZDVmZDY1YTkiLCJleHAiOjE1NTg5MDUzNjMsIm5iZiI6MCwiaWF0IjoxNTU4OTAzNTYzLCJpc3MiOiJodHRwOi8vMTk1LjIwMS4xMTAuMTIzOjQ4NjY2L2F1dGgvcmVhbG1zL2phdmF0YXItc2VjdXJpdHkiLCJhdWQiOiJpbnRlcnZpZXctc2VydmljZSIsInN1YiI6IjhkNjAwOWIwLTViZDgtNDUzMy05Y2ZhLTBjZTU1NWUyYjIyOCIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJpbnRlcnZpZXctc2VydmljZSIsImF1dGhfdGltZSI6MCwic2Vzc2lvbl9zdGF0ZSI6ImNiMjNkOWI5LTg2ODgtNDdjNS1iZWMwLTc0ZjYyMzNkZGFmZCIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIn0.JBNz3oStTMLyd68vSCMK5Fp4B3F2lGTRpH21RSFHraU";

        TokenDetails tokenDetails = client.obtainTokenDetails(REALM, params);

        assertThat(tokenDetails.getAccessToken(), is(accessToken));
        assertThat(tokenDetails.getRefreshToken(), is(refreshToken));
        assertThat(tokenDetails.getAccessExpiredIn(), is("300"));
        assertThat(tokenDetails.getRefreshExpiredIn(), is("1800"));

        HttpPost httpPost = httpPostCaptor.getValue();
        assertThat(httpPost.getURI().toString(), is("http://195.201.110.123:48666/javatar-security/path"));
        assertThat(httpPost.getAllHeaders().length, is(1));
        assertThat(httpPost.getAllHeaders()[0].getName(), is(HttpHeaders.CONTENT_TYPE));
        assertThat(httpPost.getAllHeaders()[0].getValue(), is(MediaType.APPLICATION_FORM_URLENCODED_VALUE));
    }

    @Test
    void obtainTokenDetailsErrorScenario() throws Exception {
        String realm = "realm-tenant";
        List<BasicNameValuePair> params = new ArrayList<>();

        when(oidcConfiguration.getIdentityProviderHost()).thenReturn("identity-provider.host");
        when(oidcConfiguration.getTokenEndpoint()).thenReturn("/{realm}/path");

        when(httpClient.execute(httpPostCaptor.capture())).thenReturn(httpResponse);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(HttpStatus.SC_BAD_REQUEST);   //status not OK

        BasicHttpEntity httpEntity = new BasicHttpEntity();
        httpEntity.setContent(TestHelper.getStubAsInputStream("obtain-token-error.json"));
        when(httpResponse.getEntity()).thenReturn(httpEntity);

        assertThrows(ExchangeTokenByCodeAuthenticationException.class, () ->  client.obtainTokenDetails(realm, params));
    }
}