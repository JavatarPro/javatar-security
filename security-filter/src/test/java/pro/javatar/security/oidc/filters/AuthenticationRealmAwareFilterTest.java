package pro.javatar.security.oidc.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockitoAnnotations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import pro.javatar.security.api.config.SecurityConfig;
import pro.javatar.security.oidc.SecurityConstants;
import pro.javatar.security.oidc.SecurityTestResource;
import pro.javatar.security.oidc.exceptions.RealmNotFoundAuthenticationException;
import pro.javatar.security.oidc.services.OidcAuthenticationHelper;
import pro.javatar.security.oidc.services.OidcConfiguration;
import pro.javatar.security.oidc.services.api.RealmService;
import pro.javatar.security.oidc.services.impl.RealmServiceImpl;
import pro.javatar.security.oidc.utils.MockHttpRequest;
import pro.javatar.security.oidc.utils.SpringTestConfig;

import javax.servlet.ServletException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static pro.javatar.security.oidc.filters.AuthenticationRealmAwareFilter.BASE_REALM_REGEX;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {
        SpringTestConfig.class,
        AuthenticationRealmAwareFilterTest.SpringConfig.class
})
@WebAppConfiguration
class AuthenticationRealmAwareFilterTest {

    private final static Logger logger =
            LoggerFactory.getLogger(AuthenticationRealmAwareFilterTest.class);

    @Autowired
    AuthenticationControllerAdviceFilter authenticationControllerAdviceFilter;

    AuthenticationRealmAwareFilter authenticationRealmAwareFilter;

    @Autowired
    AuthorizationStubFilter authorizationStubFilter;

    @Autowired
    SecurityTestResource securityTestResource;

    OidcConfiguration oidcConfiguration = new OidcConfiguration();

    @Autowired
    OidcAuthenticationHelper oidcAuthenticationHelper;

    @Autowired
    RealmService realmService;

    @Autowired
    WebApplicationContext wac;

    MockMvc mockMvc;

    ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setup() throws ServletException {
        MockitoAnnotations.initMocks(this);
        authenticationRealmAwareFilter = new AuthenticationRealmAwareFilter(oidcAuthenticationHelper);
        oidcConfiguration.setClientId("user-management-service");
        oidcAuthenticationHelper.setOidcConfiguration(oidcConfiguration);
        authenticationRealmAwareFilter.setRealmParamName("realm");
        authenticationRealmAwareFilter.init(null);
        authenticationControllerAdviceFilter.init(null);
        // TODO add token with "USER_READ", "USER_WRITE" permissions
//        authorizationStubFilter.setEnableFilter(true);
//        authorizationStubFilter.setAuthorities(Arrays.asList("USER_READ", "USER_WRITE"));
        this.mockMvc = MockMvcBuilders
                .standaloneSetup(this.securityTestResource)
                .setMessageConverters(new MappingJackson2HttpMessageConverter()) // Important!
                .addFilter(authenticationControllerAdviceFilter, "/*")
                .addFilter(authenticationRealmAwareFilter, "/*")
                .addFilter(authorizationStubFilter, "/*")
                .build();
        logger.info("authenticationRealmAwareFilter filter state: {}", authenticationRealmAwareFilter.toString());
    }

    @AfterEach
    void tearDown() {
        oidcAuthenticationHelper.removeRealmFromCurrentRequest();
        authenticationRealmAwareFilter.destroy();
        authenticationControllerAdviceFilter.destroy();
        oidcConfiguration.setFilterApplyUrlRegex(null);
        oidcConfiguration.setFilterApplyUrlList(Collections.emptyList());
    }

    @Test
    void realmAwareFilterDisabledScenario() throws Exception {
        authenticationRealmAwareFilter.setEnableFilter(false);
        authenticationRealmAwareFilter.setRealmMandatory(true);
        MvcResult result = mockMvc.perform(post("/security/realm/users")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header(SecurityConstants.REALM_HEADER, "realm")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(getStub("security-users-test.json")))
                .andDo(print()).andExpect(status().isCreated()).andReturn();
        String content = result.getResponse().getContentAsString();
        Map<String, String> resultMap = objectMapper.readValue(content, HashMap.class);
        assertThat(resultMap.get("name"), is("Chuck"));
        assertThat(resultMap.get("lastName"), is("Norris"));
    }

    @Test
    void filterSuccessfullySetupRealmFromHeaderForThread() throws Exception {
        authenticationRealmAwareFilter.setEnableFilter(true);
        authenticationRealmAwareFilter.setRealmMandatory(true);
        MvcResult result = mockMvc.perform(post("/security/realm/users")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header(SecurityConstants.REALM_HEADER, "realm")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(getStub("security-users-test.json")))
                .andDo(print()).andExpect(status().isCreated()).andReturn();
        String content = result.getResponse().getContentAsString();
        Map<String, String> resultMap = objectMapper.readValue(content, HashMap.class);
        assertThat(resultMap.get("name"), is("Chuck"));
        assertThat(resultMap.get("lastName"), is("Norris"));
    }

    @Test
    void filterSetupRealmFromHeaderUnauthorizedFlow() throws Exception {
        authenticationRealmAwareFilter.setEnableFilter(true);
        authenticationRealmAwareFilter.setRealmMandatory(true);
//        authorizationStubFilter.setEnableFilter(false);
        MvcResult result = mockMvc.perform(post("/security/realm/users")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(getStub("security-users-test.json")))
                .andDo(print()).andExpect(status().isUnauthorized()).andReturn();
    }

    @Test
    void retrieveRealmFromUrl() throws Exception {
        authenticationRealmAwareFilter.setEnableFilter(true);
        authenticationRealmAwareFilter.setRealmMandatory(true);
        authenticationRealmAwareFilter.setRealmUrlPattern("/security/{realm}/*");
        MvcResult result = mockMvc.perform(post("/security/some_realm/users")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(getStub("security-users-test.json")))
                .andDo(print()).andExpect(status().isCreated()).andReturn();
        String realm = result.getResponse().getHeader(SecurityConstants.REALM_HEADER);
        String content = result.getResponse().getContentAsString();
        Map<String, String> resultMap = objectMapper.readValue(content, HashMap.class);
        assertThat(realm, is("some_realm"));
        assertThat(resultMap.get("name"), is("Chuck"));
        assertThat(resultMap.get("lastName"), is("Norris"));
    }

    @Test
    void setupRealmFromParamsMockMvc() throws Exception {
        authenticationRealmAwareFilter.setEnableFilter(true);
        authenticationRealmAwareFilter.setRealmMandatory(true);
        MvcResult result = mockMvc.perform(post("/security/javatar-security/users")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .param("realm", "javatar-security")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(getStub("security-users-test.json")))
                .andDo(print()).andExpect(status().isCreated()).andReturn();
        String content = result.getResponse().getContentAsString();
        Map<String, String> resultMap = objectMapper.readValue(content, HashMap.class);
        String realm = result.getResponse().getHeader(SecurityConstants.REALM_HEADER);
        assertThat(realm, is("javatar-security"));
        assertThat(resultMap.get("name"), is("Chuck"));
        assertThat(resultMap.get("lastName"), is("Norris"));
    }

    @Test
    void shouldSkipMockMvc() throws Exception {
        authenticationRealmAwareFilter.setEnableFilter(true);
        authenticationRealmAwareFilter.setRealmMandatory(true);
        authenticationRealmAwareFilter.setFilterApplyUrlRegex("\\/security\\/.*");
        //        oidcConfiguration.setFilterApplyUrlRegex("\\/not-used-in-this-test\\/.*");
        MvcResult result = mockMvc.perform(post("/security/realm/users")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .param("realm", "realm_sk")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(getStub("security-users-test.json")))
                .andDo(print()).andExpect(status().isCreated()).andReturn();
        String content = result.getResponse().getContentAsString();
        Map<String, String> resultMap = objectMapper.readValue(content, HashMap.class);
        String realm = result.getResponse().getHeader(SecurityConstants.REALM_HEADER);
        assertThat(realm, is("realm_sk"));
        assertThat(resultMap.get("name"), is("Chuck"));
        assertThat(resultMap.get("lastName"), is("Norris"));
    }

    @Test
    void shouldSkipMockFromHelperMvc() throws Exception {
        authenticationRealmAwareFilter.setEnableFilter(true);
        authenticationRealmAwareFilter.setRealmMandatory(true);
        authenticationRealmAwareFilter.setFilterApplyUrlRegex("");
        oidcConfiguration.setFilterApplyUrlRegex("\\/mvc\\/securrity\\/.*");
        oidcConfiguration.setFilterApplyUrlList(Collections.singletonList("/security/realm/orders"));
        MvcResult result = mockMvc.perform(post("/security/realm/users")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(getStub("security-users-test.json")))
                .andDo(print()).andExpect(status().isCreated()).andReturn();
        String content = result.getResponse().getContentAsString();
        Map<String, String> resultMap = objectMapper.readValue(content, HashMap.class);
        String realm = result.getResponse().getHeader(SecurityConstants.REALM_HEADER);
        assertThat(resultMap.get("name"), is("Chuck"));
        assertThat(resultMap.get("lastName"), is("Norris"));
    }

    private AuthenticationRealmAwareFilter getFilter(){
        OidcAuthenticationHelper helper = new OidcAuthenticationHelper();
        helper.setOidcConfiguration(oidcConfiguration);
        return new AuthenticationRealmAwareFilter(helper);
    }

    @Test
    void shouldSkipByRegexp() {
        AuthenticationRealmAwareFilter authenticationRealmAwareFilter = getFilter();
        authenticationRealmAwareFilter.setFilterApplyUrlRegex("\\/users\\/.*");
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/users/id")), is(false));
    }

    @Test
    void shouldSkipByList() {
        AuthenticationRealmAwareFilter authenticationRealmAwareFilter = getFilter();
        authenticationRealmAwareFilter.setFilterApplyUrlList(Arrays.asList("/users/id", "/users/get"));
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/users/id")), is(false));
    }

    @Test
    void shouldSkip(){
        AuthenticationRealmAwareFilter authenticationRealmAwareFilter = getFilter();
        authenticationRealmAwareFilter.setFilterApplyUrlRegex("\\/users\\/.*");
        authenticationRealmAwareFilter.setFilterApplyUrlList(Arrays.asList("/orders/id", "/orders/get"));
        authenticationRealmAwareFilter.setFilterIgnoreUrls(Collections.emptyList());
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/users/id")), is(false));
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/orders/id")), is(false));
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/contacts/id")), is(true));

        authenticationRealmAwareFilter.setFilterApplyUrlRegex("\\/users\\/.*");
        authenticationRealmAwareFilter.setFilterApplyUrlList(Collections.singletonList("/orders/*"));
        authenticationRealmAwareFilter.setFilterIgnoreUrls(Collections.singletonList("/users/id"));
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/users/id")), is(true));
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/orders/id")), is(false));
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/contacts/id")), is(true));

        authenticationRealmAwareFilter.setFilterApplyUrlList(Collections.singletonList("/orders/*"));
        authenticationRealmAwareFilter.setFilterIgnoreUrls(Collections.emptyList());
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/users/id")), is(false));
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/orders/id")), is(false));
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/contacts/id")), is(true));

        authenticationRealmAwareFilter.setFilterApplyUrlRegex("");
        authenticationRealmAwareFilter.setFilterApplyUrlList(Arrays.asList("/orders/*", "/users/*"));
        authenticationRealmAwareFilter.setFilterIgnoreUrls(Collections.emptyList());
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/users/id")), is(false));
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/orders/id")), is(false));
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/contacts/id")), is(true));
    }

    @Test
    void shouldSkipFromHelper() {
        AuthenticationRealmAwareFilter filter = getFilter();
        oidcConfiguration.setFilterApplyUrlRegex("\\/security\\/rest\\/.*");
        assertThat(filter.shouldSkip(MockHttpRequest.mockGetUri("/security/rest/users/id")), is(false));
        oidcConfiguration.setFilterApplyUrlList(Arrays.asList("/users/id", "/users/get"));
        assertThat(filter.shouldSkip(MockHttpRequest.mockGetUri("/users/id")), is(false));
    }

    private String getStub(String classpathFile) throws Exception {
        return new String(Files.readAllBytes(Paths.get(getClass().getClassLoader().getResource(classpathFile).toURI())));
    }

    @Test
    void setupRealmForCurrentRequestThread() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        // TODO
    }

    @Test
    void setupRealmFromParams() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        authenticationRealmAwareFilter.setupRealmFromParams(request);
        String actualRealm = oidcAuthenticationHelper.getRealmForCurrentRequest();
//         assertThat(actualRealm, is(nullValue()));
        // TODO verify why need this behaviour with default realm
        assertThat(actualRealm, is("javatar-security")); // default realm is provided

        request.addParameter("realm", "realm");
        authenticationRealmAwareFilter.setupRealmFromParams(request);
        actualRealm = oidcAuthenticationHelper.getRealmForCurrentRequest();
        assertThat(actualRealm, is("realm"));
    }

    @Test
    void containsRealmHeader() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        assertThat(authenticationRealmAwareFilter.containsRealmHeader(request), is(false));
        request.addHeader(SecurityConstants.REALM_HEADER, "realm");
        assertThat(authenticationRealmAwareFilter.containsRealmHeader(request), is(true));
    }

    @Test
    void setupRealmFromHeader() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(SecurityConstants.REALM_HEADER, "realm");
        authenticationRealmAwareFilter.setupRealmFromHeader(request);
        String actualRealm = oidcAuthenticationHelper.getRealmForCurrentRequest();
        assertThat(actualRealm, is("realm"));
    }

    @Test
    void isUrlRetrieverEnabled() {
        assertThat(authenticationRealmAwareFilter.isUrlRetrieverEnabled(), is(false));
        authenticationRealmAwareFilter.setRealmUrlPattern("/security/realm/users");
        assertThat(authenticationRealmAwareFilter.isUrlRetrieverEnabled(), is(false));
        authenticationRealmAwareFilter.setRealmUrlPattern("/security/{some_realm}/users");
        assertThat(authenticationRealmAwareFilter.isUrlRetrieverEnabled(), is(false));
        authenticationRealmAwareFilter.setRealmUrlPattern("/security/{realm}/users");
        assertThat(authenticationRealmAwareFilter.isUrlRetrieverEnabled(), is(true));
    }

    @Test
    void isSuccessfulSetupRealmFromUri() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        authenticationRealmAwareFilter.setRealmUrlPattern("/security/{realm}/users");
        request.setRequestURI("/index.html");
        assertThat(authenticationRealmAwareFilter.isSuccessfulSetupRealmFromUri(request), is(false));
        request.setRequestURI("/security/realm/users");
        assertThat(authenticationRealmAwareFilter.isSuccessfulSetupRealmFromUri(request), is(true));
        request.setRequestURI("/security/users");
        assertThat(authenticationRealmAwareFilter.isSuccessfulSetupRealmFromUri(request), is(false));
    }

    @Test
    void validateRealmSetup() {
        authenticationRealmAwareFilter.setRealmMandatory(true);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(SecurityConstants.REALM_HEADER, "realm");
        authenticationRealmAwareFilter.setupRealmForCurrentRequestThread(request);
        authenticationRealmAwareFilter.validateRealmSetup();
    }

    @Test
    void validateRealmSetupRealmNotMandatory() {
        unsetDefaultRealm();
        authenticationRealmAwareFilter.setRealmMandatory(false);
        authenticationRealmAwareFilter.validateRealmSetup();
    }

    @Test
    void validateRealmSetupWithException() {
        unsetDefaultRealm();
        authenticationRealmAwareFilter.setRealmMandatory(true);
        assertThrows(RealmNotFoundAuthenticationException.class, () -> authenticationRealmAwareFilter.validateRealmSetup());
    }

    @Test
    void prepareRealmRegex() {
        String realmRegex = authenticationRealmAwareFilter.prepareRealmRegex("/security/{realm}");
        assertThat(realmRegex, is(BASE_REALM_REGEX));
        realmRegex = authenticationRealmAwareFilter.prepareRealmRegex("/security/tenant-{realm}");
        assertThat(realmRegex, is(BASE_REALM_REGEX));
        realmRegex = authenticationRealmAwareFilter.prepareRealmRegex("/security/realm-{realm}/*");
        assertThat(realmRegex, is("([^/]{2,})"));
        realmRegex = authenticationRealmAwareFilter.prepareRealmRegex("/security/{realm}-tenant/*");
        assertThat(realmRegex, is("([^-]{2,})"));
    }

    @Test
    void setupRealmInResponse() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        String realm = "SOME_REALM";
        request.addHeader(SecurityConstants.REALM_HEADER, realm);
        authenticationRealmAwareFilter.setupRealmFromHeader(request);

        MockHttpServletResponse response = new MockHttpServletResponse();
        authenticationRealmAwareFilter.setupRealmInResponse(response);
        assertThat(response.getHeader(SecurityConstants.REALM_HEADER), is(realm));
    }

    @Test
    void shouldSkipGetMethods() {
        AuthenticationRealmAwareFilter filter = getFilter();
        oidcConfiguration.setFilterApplyUrlRegex("\\/security\\/rest\\/.*");
        oidcConfiguration.setFilterIgnoreUrlList(Collections.singletonList("GET /*"));
        assertThat(filter.shouldSkip(MockHttpRequest.mockGetUri("/security/rest/users/id")), is(true));
        assertThat(filter.shouldSkip(MockHttpRequest.mockMethodAndUri(HttpMethod.POST, "/security/rest/users")), is(false));
        assertThat(filter.shouldSkip(MockHttpRequest.mockMethodAndUri(HttpMethod.DELETE, "/security/rest/users/id")), is(false));
        assertThat(filter.shouldSkip(MockHttpRequest.mockMethodAndUri(HttpMethod.PATCH, "/security/rest/users/id")), is(false));
    }

    void unsetDefaultRealm() {
        SecurityConfig tmpConfig = mock(SecurityConfig.class);
        SecurityConfig.IdentityProvider identityProvider = mock(SecurityConfig.IdentityProvider.class);
        when(tmpConfig.identityProvider()).thenReturn(identityProvider);
        //when(identityProvider.realm()).thenReturn(null);
        ((RealmServiceImpl)realmService).setConfig(tmpConfig);
    }

    @ComponentScan("pro.javatar.security")
    public static class SpringConfig {

        public SecurityConfig securityConfig() {
            return new SecurityConfig() {

                @Override
                public List<String> applyUrls() {
                    return null;
                }

                @Override
                public List<String> ignoreUrls() {
                    return null;
                }

                @Override
                public SecurityFilter securityFilter() {
                    return new SecurityFilter() {
                        @Override
                        public boolean isAnonymousAllowed() {
                            return false;
                        }

                        @Override
                        public boolean isJwtBearerFilterEnable() {
                            return true;
                        }

                        @Override
                        public boolean isJwtBearerTokenOtherAuthenticationAllowed() {
                            return false;
                        }
                    };
                }

                @Override
                public boolean isSkipRefererCheck() {
                    return false;
                }

                @Override
                public Redirect redirect() {
                    return new Redirect() {
                        @Override
                        public boolean enabled() {
                            return false;
                        }

                        @Override
                        public boolean isUseReferAsRedirectUri() {
                            return false;
                        }

                        @Override
                        public String redirectUrl() {
                            return null;
                        }
                    };
                }

                @Override
                public IdentityProvider identityProvider() {
                    return null;
                }

                @Override
                public Boolean useReferAsRedirectUri() {
                    return null;
                }

                @Override
                public String publicKeysStorage() {
                    return null;
                }

                @Override
                public String tokenStorage() {
                    return null;
                }

                @Override
                public Storage storage() {
                    return null;
                }

                @Override
                public TokenValidation tokenValidation() {
                    return null;
                }

                @Override
                public Stub stub() {
                    return null;
                }

                @Override
                public HttpClient httpClient() {
                    return null;
                }

                @Override
                public Application application() {
                    return null;
                }

                @Override
                public String errorDescriptionLink() {
                    return null;
                }
            };
        }
    }

}