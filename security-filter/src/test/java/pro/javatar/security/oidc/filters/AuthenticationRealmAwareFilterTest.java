package pro.javatar.security.oidc.filters;

import static org.mockito.Mockito.mock;
import static pro.javatar.security.oidc.filters.AuthenticationRealmAwareFilter.BASE_REALM_REGEX;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import pro.javatar.security.RealmPublicKeyCacheService;
import pro.javatar.security.oidc.SecurityConstants;
import pro.javatar.security.oidc.SecurityTestResource;
import pro.javatar.security.oidc.exceptions.RealmNotFoundAuthenticationException;
import pro.javatar.security.oidc.services.OidcAuthenticationHelper;
import pro.javatar.security.oidc.services.OidcConfiguration;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
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
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import pro.javatar.security.oidc.utils.MockHttpRequest;
import pro.javatar.security.oidc.utils.SpringTestConfig;

import javax.servlet.ServletException;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RunWith(SpringRunner.class)
@ContextConfiguration(classes = {
        SpringTestConfig.class,
        AuthenticationRealmAwareFilterTest.SpringConfig.class
})
@WebAppConfiguration
public class AuthenticationRealmAwareFilterTest {

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

    private OidcAuthenticationHelper oidcAuthenticationHelper = new OidcAuthenticationHelper();

    @Autowired
    WebApplicationContext wac;

    MockMvc mockMvc;

    ObjectMapper objectMapper = new ObjectMapper();

    @Before
    public void setup() throws ServletException {
        MockitoAnnotations.initMocks(this);
        authenticationRealmAwareFilter = new AuthenticationRealmAwareFilter(oidcAuthenticationHelper);
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

    @After
    public void tearDown() throws Exception {
        oidcAuthenticationHelper.removeRealmFromCurrentRequest();
        authenticationRealmAwareFilter.destroy();
        authenticationControllerAdviceFilter.destroy();
        oidcConfiguration.setFilterApplyUrlRegex(null);
        oidcConfiguration.setFilterApplyUrlList(Collections.emptyList());
    }

    @Test
    public void realmAwareFilterDisabledScenario() throws Exception {
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
    public void filterSuccessfullySetupRealmFromHeaderForThread() throws Exception {
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
    public void filterSetupRealmFromHeaderUnauthorizedFlow() throws Exception {
        authenticationRealmAwareFilter.setEnableFilter(true);
        authenticationRealmAwareFilter.setRealmMandatory(true);
        MvcResult result = mockMvc.perform(post("/security/realm/users")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(getStub("security-users-test.json")))
                .andDo(print()).andExpect(status().isUnauthorized()).andReturn();
    }

    @Test
    public void retrieveRealmFromUrl() throws Exception {
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
    public void setupRealmFromParamsMockMvc() throws Exception {
        authenticationRealmAwareFilter.setEnableFilter(true);
        authenticationRealmAwareFilter.setRealmMandatory(true);
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
    public void shouldSkipMockMvc() throws Exception {
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
    public void shouldSkipMockFromHelperMvc() throws Exception {
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
    public void shouldSkipByRegexp() {
        AuthenticationRealmAwareFilter authenticationRealmAwareFilter = getFilter();
        authenticationRealmAwareFilter.setFilterApplyUrlRegex("\\/users\\/.*");
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/users/id")), is(false));
    }

    @Test
    public void shouldSkipByList() {
        AuthenticationRealmAwareFilter authenticationRealmAwareFilter = getFilter();
        authenticationRealmAwareFilter.setFilterApplyUrlList(Arrays.asList("/users/id", "/users/get"));
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/users/id")), is(false));
    }

    @Test
    public void shouldSkip(){
        AuthenticationRealmAwareFilter authenticationRealmAwareFilter = getFilter();
        authenticationRealmAwareFilter.setFilterApplyUrlRegex("\\/users\\/.*");
        authenticationRealmAwareFilter.setFilterApplyUrlList(Arrays.asList("/orders/id", "/orders/get"));
        authenticationRealmAwareFilter.setFilterIgnoreUrls(Collections.EMPTY_LIST);
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/users/id")), is(false));
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/orders/id")), is(false));
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/contacts/id")), is(true));

        authenticationRealmAwareFilter.setFilterApplyUrlRegex("\\/users\\/.*");
        authenticationRealmAwareFilter.setFilterApplyUrlList(Arrays.asList("/orders/*"));
        authenticationRealmAwareFilter.setFilterIgnoreUrls(Arrays.asList("/users/id"));
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/users/id")), is(true));
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/orders/id")), is(false));
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/contacts/id")), is(true));

        authenticationRealmAwareFilter.setFilterApplyUrlList(Arrays.asList("/orders/*"));
        authenticationRealmAwareFilter.setFilterIgnoreUrls(Collections.EMPTY_LIST);
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/users/id")), is(false));
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/orders/id")), is(false));
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/contacts/id")), is(true));

        authenticationRealmAwareFilter.setFilterApplyUrlRegex("");
        authenticationRealmAwareFilter.setFilterApplyUrlList(Arrays.asList("/orders/*", "/users/*"));
        authenticationRealmAwareFilter.setFilterIgnoreUrls(Collections.EMPTY_LIST);
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/users/id")), is(false));
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/orders/id")), is(false));
        assertThat(authenticationRealmAwareFilter.shouldSkip(MockHttpRequest.mockGetUri("/contacts/id")), is(true));
    }

    @Test
    public void shouldSkipFromHelper() throws Exception {
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
    public void setupRealmForCurrentRequestThread() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        // TODO
    }

    @Test
    public void setupRealmFromParams() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        authenticationRealmAwareFilter.setupRealmFromParams(request);
        String actualRealm = oidcAuthenticationHelper.getRealmForCurrentRequest();
        assertThat(actualRealm, is(nullValue()));

        request.addParameter("realm", "realm");
        authenticationRealmAwareFilter.setupRealmFromParams(request);
        actualRealm = oidcAuthenticationHelper.getRealmForCurrentRequest();
        assertThat(actualRealm, is("realm"));
    }

    @Test
    public void containsRealmHeader() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        assertThat(authenticationRealmAwareFilter.containsRealmHeader(request), is(false));
        request.addHeader(SecurityConstants.REALM_HEADER, "realm");
        assertThat(authenticationRealmAwareFilter.containsRealmHeader(request), is(true));
    }

    @Test
    public void setupRealmFromHeader() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(SecurityConstants.REALM_HEADER, "realm");
        authenticationRealmAwareFilter.setupRealmFromHeader(request);
        String actualRealm = oidcAuthenticationHelper.getRealmForCurrentRequest();
        assertThat(actualRealm, is("realm"));
    }

    @Test
    public void isUrlRetrieverEnabled() throws Exception {
        assertThat(authenticationRealmAwareFilter.isUrlRetrieverEnabled(), is(false));
        authenticationRealmAwareFilter.setRealmUrlPattern("/security/realm/users");
        assertThat(authenticationRealmAwareFilter.isUrlRetrieverEnabled(), is(false));
        authenticationRealmAwareFilter.setRealmUrlPattern("/security/{some_realm}/users");
        assertThat(authenticationRealmAwareFilter.isUrlRetrieverEnabled(), is(false));
        authenticationRealmAwareFilter.setRealmUrlPattern("/security/{realm}/users");
        assertThat(authenticationRealmAwareFilter.isUrlRetrieverEnabled(), is(true));
    }

    @Test
    public void isSuccessfulSetupRealmFromUri() throws Exception {
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
    public void validateRealmSetup() throws Exception {
        authenticationRealmAwareFilter.setRealmMandatory(true);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(SecurityConstants.REALM_HEADER, "realm");
        authenticationRealmAwareFilter.setupRealmForCurrentRequestThread(request);
        authenticationRealmAwareFilter.validateRealmSetup();
    }

    @Test
    public void validateRealmSetupRealmNotMandatory() throws Exception {
        authenticationRealmAwareFilter.setRealmMandatory(false);
        authenticationRealmAwareFilter.validateRealmSetup();
    }

    @Test(expected = RealmNotFoundAuthenticationException.class)
    public void validateRealmSetupWithException() throws Exception {
        authenticationRealmAwareFilter.setRealmMandatory(true);
        authenticationRealmAwareFilter.validateRealmSetup();
    }

    @Test
    public void prepareRealmRegex() throws Exception {
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
    public void setupRealmInResponse() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        String realm = "SOME_REALM";
        request.addHeader(SecurityConstants.REALM_HEADER, realm);
        authenticationRealmAwareFilter.setupRealmFromHeader(request);

        MockHttpServletResponse response = new MockHttpServletResponse();
        authenticationRealmAwareFilter.setupRealmInResponse(response);
        assertThat(response.getHeader(SecurityConstants.REALM_HEADER), is(realm));
    }

    @Test
    public void shouldSkipGetMethods() throws Exception {
        AuthenticationRealmAwareFilter filter = getFilter();
        oidcConfiguration.setFilterApplyUrlRegex("\\/security\\/rest\\/.*");
        oidcConfiguration.setFilterIgnoreUrlList(Collections.singletonList("GET /*"));
        assertThat(filter.shouldSkip(MockHttpRequest.mockGetUri("/security/rest/users/id")), is(true));
        assertThat(filter.shouldSkip(MockHttpRequest.mockMethodAndUri(HttpMethod.POST, "/security/rest/users")), is(false));
        assertThat(filter.shouldSkip(MockHttpRequest.mockMethodAndUri(HttpMethod.DELETE, "/security/rest/users/id")), is(false));
        assertThat(filter.shouldSkip(MockHttpRequest.mockMethodAndUri(HttpMethod.PATCH, "/security/rest/users/id")), is(false));
    }

    @ComponentScan("pro.javatar.security")
    public static class SpringConfig {

        @Primary
        @Bean
        public RealmPublicKeyCacheService getRealmPublicKeyCacheService() {
            return mock(RealmPublicKeyCacheService.class);
        }
    }

}