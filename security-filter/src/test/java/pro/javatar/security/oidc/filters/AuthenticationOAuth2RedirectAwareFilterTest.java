package pro.javatar.security.oidc.filters;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import pro.javatar.security.api.config.SecurityConfig;
import pro.javatar.security.oidc.SecurityTestFilter;
import pro.javatar.security.oidc.SecurityTestResource;
import pro.javatar.security.oidc.services.OidcAuthenticationHelper;
import pro.javatar.security.oidc.services.OidcConfiguration;
import pro.javatar.security.oidc.utils.SpringTestConfig;

import javax.servlet.ServletException;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static pro.javatar.security.oidc.services.OidcConfiguration.AUTHORIZATION_ENDPOINT;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {
        SpringTestConfig.class,
        AuthenticationOAuth2RedirectAwareFilterTest.SpringConfig.class
})
@WebAppConfiguration
class AuthenticationOAuth2RedirectAwareFilterTest {

    private static final String REALM = "javatar-security";

    @Autowired
    AuthenticationControllerAdviceFilter authenticationControllerAdviceFilter;

    @Autowired
    AuthenticationRealmAwareFilter authenticationRealmAwareFilter;

    AuthenticationOAuth2RedirectAwareFilter redirectAwareFilter;

    @Autowired
    SecurityTestResource securityTestResource;

    @Autowired
    SecurityTestFilter securityTestFilter;

    @Autowired
    AuthorizationStubFilter authorizationStubFilter;

    @Autowired
    OidcAuthenticationHelper oidcAuthenticationHelper;

    @Autowired
    OidcConfiguration oidcConfiguration;

    @Autowired
    SecurityConfig securityConfig;

    @Autowired
    WebApplicationContext wac;

    MockMvc mockMvc;

    @BeforeEach
    void setup() throws ServletException {
        MockitoAnnotations.initMocks(this);
        authenticationRealmAwareFilter.setEnableFilter(true);
        authenticationRealmAwareFilter.setRealmMandatory(true);
        oidcConfiguration.setAuthorizationEndpoint(AUTHORIZATION_ENDPOINT);
        // TODO token with user-management-service permissions
        // oidcConfiguration.setClientId("client_id");
        oidcConfiguration.setClientId("user-management-service");
        oidcAuthenticationHelper.setOidcConfiguration(oidcConfiguration);
        redirectAwareFilter = new AuthenticationOAuth2RedirectAwareFilter(
                authorizationStubFilter,
                oidcAuthenticationHelper,
                oidcConfiguration,
                securityConfig
        );
        redirectAwareFilter.init(null);
        // TODO add token with "USER_READ", "USER_WRITE" permissions
//        authorizationStubFilter.setEnableFilter(true);
//        authorizationStubFilter.setAuthorities(Arrays.asList("USER_READ", "USER_WRITE"));
        this.mockMvc = MockMvcBuilders
                .standaloneSetup(this.securityTestResource)
                .setMessageConverters(new MappingJackson2HttpMessageConverter()) // Important!
                .addFilter(authenticationControllerAdviceFilter, "/*")
                .addFilter(authenticationRealmAwareFilter, "/*")
                .addFilter(redirectAwareFilter, "/*")
                .addFilter(authorizationStubFilter, "/*")
                .addFilter(securityTestFilter, "/*")
                .build();
    }

    @AfterEach
    void tearDown() {
        oidcAuthenticationHelper.removeRealmFromCurrentRequest();
        redirectAwareFilter.destroy();
    }

    @Test
    void redirectAwareFilterDisabledAndReturnWithException() throws Exception {
        redirectAwareFilter.setEnableFilter(false);
        securityTestFilter.state = SecurityTestFilter.State.FAIL;
        mockMvc.perform(post("/security/realm/users")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .param("realm", "realm_sk")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(getStub("security-users-test.json")))
                .andDo(print()).andExpect(status().isUnauthorized()).andReturn();
    }

    @Test
    void redirectAwareFilterDisabledAndSimpleReturn() throws Exception {
        redirectAwareFilter.setEnableFilter(false);
        securityTestFilter.state = SecurityTestFilter.State.SKIP;
        mockMvc.perform(get("/security/realm/users/456")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .param("realm", REALM)
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(getStub("security-users-test.json")))
                .andDo(print()).andExpect(status().isOk()).andReturn();
    }

    @Test
    void redirectAwareFilterEnabled() throws Exception {
        redirectAwareFilter.setEnableFilter(true);
        securityTestFilter.state = SecurityTestFilter.State.BEARER_NOT_FOUND;
        // TODO disable filter by not creating it
        authorizationStubFilter.setEnableFilter(false);
        mockMvc.perform(post("/security/realm/users")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .param("realm", "javatar-security")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(getStub("security-users-test.json")))
                .andDo(print()).andExpect(status().isFound()).andReturn();
        authorizationStubFilter.setEnableFilter(true);
    }

    @Disabled // we do not support regex any more
    @Test
    void redirectAwareFilterShouldSkipScenario() throws Exception {
//        oidcConfiguration.setFilterApplyUrlRegex("/some-other-url");
        redirectAwareFilter.setEnableFilter(true);
        // redirectAwareFilter.setFilterApplyUrlRegex("\\/wrong-url-pattern\\/realm\\/.*");
        securityTestFilter.state = SecurityTestFilter.State.FAIL;
        mockMvc.perform(post("/security/realm/users")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .param("realm", "realm_sk")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(getStub("security-users-test.json")))
                .andDo(print()).andExpect(status().isUnauthorized()).andReturn();
    }

    @Disabled // we do not support regex any more
    @Test
    void redirectAwareFilterShouldListSkipScenario() throws Exception {
        redirectAwareFilter.setEnableFilter(true);
        // redirectAwareFilter.setFilterApplyUrlList(Collections.singletonList("/realm/users"));
        securityTestFilter.state = SecurityTestFilter.State.FAIL;
        mockMvc.perform(post("/security/realm/users")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .param("realm", "realm_sk")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(getStub("security-users-test.json")))
                .andDo(print()).andExpect(status().isUnauthorized()).andReturn();
    }

    @Test
    void redirectAwareFilterShouldSkipFromHelperScenario() throws Exception {
        oidcConfiguration.setFilterApplyUrlRegex("/some-other-url");
        redirectAwareFilter.setEnableFilter(true);
        securityTestFilter.state = SecurityTestFilter.State.FAIL;
        mockMvc.perform(post("/security/realm/users")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .param("realm", "realm_sk")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(getStub("security-users-test.json")))
                .andDo(print()).andExpect(status().isUnauthorized()).andReturn();
        oidcConfiguration.setFilterApplyUrlList(Collections.singletonList("/another-url"));
        mockMvc.perform(post("/security/realm/users")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .param("realm", "realm_sk")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(getStub("security-users-test.json")))
                .andDo(print()).andExpect(status().isUnauthorized()).andReturn();
    }

    @Test
    void redirectAwareFilterAllPassedNoRedirectNeeded() throws Exception {
        redirectAwareFilter.setEnableFilter(true);
        securityTestFilter.state = SecurityTestFilter.State.SKIP;
        mockMvc.perform(get("/security/realm/users/156")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .param("realm", REALM)
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(getStub("security-users-test.json")))
                .andDo(print()).andExpect(status().isOk()).andReturn();
    }

    @Test
    void redirectToAuthorizationEndpointScenario() throws Exception {
        String realm = "realm_sk";
        String clientId = "seat-matching";
        String identityProviderHost = "https://ip.javatar.pro";
        String redirectUrl = identityProviderHost + oidcConfiguration.getAuthorizationEndpoint().
                replace(OidcConfiguration.CLIENT_ID_PLACEHOLDER, clientId).
                replace(OidcConfiguration.REALM_PLACEHOLDER, realm);

        redirectAwareFilter.setEnableFilter(true);
        oidcConfiguration.setClientId(clientId);
        oidcConfiguration.setIdentityProviderHost(identityProviderHost);
        securityTestFilter.state = SecurityTestFilter.State.BEARER_NOT_FOUND;
        // TODO disable filter
        authorizationStubFilter.setEnableFilter(false);
        MvcResult mvcResult = mockMvc.perform(get("/security/realm/users/156")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .param("realm", realm)
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(getStub("security-users-test.json")))
                .andDo(print()).andExpect(status().isFound()).andReturn();
        String expectedRedirectUrl = mvcResult.getResponse().getRedirectedUrl();
        redirectUrl = redirectUrl.replace(OidcConfiguration.REDIRECT_URI_PLACEHOLDER,
                URLEncoder.encode(mvcResult.getRequest().getRequestURL().toString(),  "UTF-8"));
        assertThat(expectedRedirectUrl, is(redirectUrl));
        authorizationStubFilter.setEnableFilter(true);
    }

    private String getStub(String classpathFile) throws Exception {
        return new String(Files.readAllBytes(Paths.get(getClass().getClassLoader().getResource(classpathFile).toURI())));
    }

    @ComponentScan("pro.javatar.security")
    public static class SpringConfig {
    }
}