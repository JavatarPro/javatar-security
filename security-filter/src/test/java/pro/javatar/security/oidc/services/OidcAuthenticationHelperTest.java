package pro.javatar.security.oidc.services;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pro.javatar.security.api.config.SecurityConfig;
import pro.javatar.security.oidc.model.OAuth2Constants;
import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.SecurityConstants;
import pro.javatar.security.oidc.exceptions.TokenSignedForOtherRealmAuthorizationException;
import pro.javatar.security.oidc.filters.AuthenticationJwtBearerTokenAwareFilter;

import org.apache.http.HttpHeaders;
import org.mockito.Mockito;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import pro.javatar.security.oidc.services.api.RealmService;
import pro.javatar.security.oidc.services.impl.RealmServiceImpl;
import pro.javatar.security.oidc.utils.SpringTestConfig;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.LocalDateTime;

class OidcAuthenticationHelperTest {

    private OidcAuthenticationHelper helper;

    @BeforeEach
    void setUp() {
        SecurityConfig config = new SpringTestConfig().securityConfig();
        RealmService realmService = new RealmServiceImpl(config);
        helper = new OidcAuthenticationHelper();
        helper.setConfig(config);
        helper.setRealmService(realmService);
    }

    @Test
    void getBearerTokenFromRequest() {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("");
        assertThat(helper.getBearerToken(request), is(nullValue()));
        Mockito.reset(request);

        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(null);
        assertThat(helper.getBearerToken(request), is(nullValue()));
        Mockito.reset(request);

        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer token111");
        assertThat(helper.getBearerToken(request), is("token111"));
        Mockito.reset(request);

        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("token222");
        assertThat(helper.getBearerToken(request), is("token222"));
    }

    @Test
    void getBearerTokenFromResponse() {
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        when(response.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("");
        assertThat(helper.getBearerToken(response), is(nullValue()));
        Mockito.reset(response);

        when(response.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(null);
        assertThat(helper.getBearerToken(response), is(nullValue()));
        Mockito.reset(response);

        when(response.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer token111");
        assertThat(helper.getBearerToken(response), is("token111"));
        Mockito.reset(response);

        when(response.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("token222");
        assertThat(helper.getBearerToken(response), is("token222"));
    }

    @Test
    void getRefreshTokenFromRequest() throws Exception {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        when(request.getHeader(SecurityConstants.REFRESH_TOKEN_HEADER)).thenReturn("token333");
        assertThat(helper.getRefreshToken(request), is("token333"));
    }

    @Test
    void getRefreshTokenFromResponse() {
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        when(response.getHeader(SecurityConstants.REFRESH_TOKEN_HEADER)).thenReturn("token444");
        assertThat(helper.getRefreshToken(response), is("token444"));
    }

    @Test
    void realmForCurrentRequest() {
        OidcConfiguration oidcConfiguration = new OidcConfiguration();
        helper.setOidcConfiguration(oidcConfiguration);
        //if realm is not set it will be got as default
        assertThat(helper.getRealmForCurrentRequest(), is("javatar-security"));

        helper.setRealmForCurrentRequest("realm2");
        assertThat(helper.getRealmForCurrentRequest(), is("realm2"));

        helper.removeRealmFromCurrentRequest();
        assertThat(helper.getRealmForCurrentRequest(), is("javatar-security"));
    }

    @Test
    void removeCodeFromRequest() {
        HttpServletRequest request = mock(HttpServletRequest.class);

        String secureCode = "secure_code";
        when(request.getParameter(eq(OAuth2Constants.CODE))).thenReturn(secureCode);
        String requestUrl = "http://mvc.javatar.pro/realm/index.html?code=";
        when(request.getRequestURL()).thenReturn(new StringBuffer(requestUrl).append(secureCode).append("&startDate=11-11-12"));

        String url = helper.removeCodeFromUrl(request);
        assertFalse(url.contains("code="));

        reset(request);

        when(request.getParameter(eq(OAuth2Constants.CODE))).thenReturn(secureCode);
        requestUrl = "http://mvc.javatar.pro/realm/index.html?param1=12345&code=";
        when(request.getRequestURL()).thenReturn(new StringBuffer(requestUrl).append(secureCode).append("&startDate=11-11-12"));

        url = helper.removeCodeFromUrl(request);
        assertFalse(url.contains("code="));
    }

    @Test
    void removeCodeFromUrl() {
        assertThat(helper.removeCodeFromUrl("http://mvc.javatar.pro/realm/index.html?param1=12345&code=secure_code", "secure_code"),
                is("http://mvc.javatar.pro/realm/index.html?param1=12345"));
        assertThat(helper.removeCodeFromUrl("http://mvc.javatar.pro/realm/index.html?code=secure_code&param1=12345", "secure_code"),
                is("http://mvc.javatar.pro/realm/index.html?&param1=12345"));
        assertThat(helper.removeCodeFromUrl("http://mvc.javatar.pro/realm/index.html?param1=12345", "secure_code"),
                is("http://mvc.javatar.pro/realm/index.html?param1=12345"));
    }

    @Test
    void validateRealmException() {
        OidcConfiguration oidcConfiguration = new OidcConfiguration();
        oidcConfiguration.setDefaultRealm("realm"); //resource realm
        oidcConfiguration.setExcludeValidationRealm("mservice");
        helper.setOidcConfiguration(oidcConfiguration);

        TokenDetails tokenDetails = new TokenDetails();
        tokenDetails.setRealm("realm2");
        assertThrows(TokenSignedForOtherRealmAuthorizationException.class, () -> helper.validateRealm(tokenDetails));
    }

    @Test
    void validateRealm() {
        OidcConfiguration oidcConfiguration = new OidcConfiguration();
        oidcConfiguration.setDefaultRealm("realm");  //resource realm
        oidcConfiguration.setExcludeValidationRealm("mservice");
        helper.setOidcConfiguration(oidcConfiguration);

        TokenDetails tokenDetails = new TokenDetails();
        tokenDetails.setRealm("javatar-security");
        helper.validateRealm(tokenDetails);

        tokenDetails.setRealm("javatar-security");
        helper.validateRealm(tokenDetails);
    }

    @Test
    void isTokenExpiredOrShouldBeRefreshed() {
        OidcConfiguration oidcConfiguration = new OidcConfiguration() {
            @Override
            public int getTokenShouldBeRefreshed() {
                return 75; //default value
            }
        };
        helper.setOidcConfiguration(oidcConfiguration);
        TokenDetails tokenDetails = new TokenDetails();
        assertThat(helper.isTokenExpiredOrShouldBeRefreshed(tokenDetails), is(true));

        tokenDetails.setAccessTokenExpiration(LocalDateTime.now().plusMinutes(5));
        assertThat(helper.isTokenExpiredOrShouldBeRefreshed(tokenDetails), is(false));

        tokenDetails.setAccessTokenExpiration(LocalDateTime.now().plusMinutes(1)); //less then default value
        assertThat(helper.isTokenExpiredOrShouldBeRefreshed(tokenDetails), is(true));
    }

    @Test
    void safeCleanupSecurityContext() {
        SecurityContextHolder.clearContext();
        assertThat(SecurityContextHolder.getContext().getAuthentication(), is(nullValue()));
        TokenDetails tokenDetails = new TokenDetails();
        tokenDetails.setCredentialsProvider(AuthenticationJwtBearerTokenAwareFilter.class);
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("admin", tokenDetails));
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Class credentialsProvider =
                ((TokenDetails) authentication.getCredentials()).getCredentialsProvider();
        assertThat(authentication, is(notNullValue()));
        assertThat(credentialsProvider, is(equalTo(AuthenticationJwtBearerTokenAwareFilter.class)));

        helper.safeCleanupSecurityContext(AuthenticationJwtBearerTokenAwareFilter.class);
        assertThat(SecurityContextHolder.getContext().getAuthentication(), is(nullValue()));

        //another provider inside security context
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("admin", tokenDetails));
        authentication = SecurityContextHolder.getContext().getAuthentication();
        credentialsProvider =
                ((TokenDetails) authentication.getCredentials()).getCredentialsProvider();
        assertThat(authentication, is(notNullValue()));
        assertThat(credentialsProvider, is(equalTo(AuthenticationJwtBearerTokenAwareFilter.class)));

        authentication = SecurityContextHolder.getContext().getAuthentication();
        credentialsProvider =
                ((TokenDetails) authentication.getCredentials()).getCredentialsProvider();
        assertThat(authentication, is(notNullValue()));
        assertThat(credentialsProvider, is(equalTo(AuthenticationJwtBearerTokenAwareFilter.class)));
    }

}