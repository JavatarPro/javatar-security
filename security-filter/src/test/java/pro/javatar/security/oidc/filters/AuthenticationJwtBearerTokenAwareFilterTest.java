package pro.javatar.security.oidc.filters;

import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import pro.javatar.security.oidc.model.OAuth2Constants;
import pro.javatar.security.oidc.SecurityTestFilter;
import pro.javatar.security.oidc.SecurityTestResource;
import pro.javatar.security.oidc.services.OAuth2AuthorizationFlowService;
import pro.javatar.security.oidc.services.OidcAuthenticationHelper;
import pro.javatar.security.oidc.services.OidcConfiguration;

import com.fasterxml.jackson.databind.ObjectMapper;
import pro.javatar.security.oidc.utils.SpringTestConfig;
import pro.javatar.security.oidc.utils.TestHelper;
import org.apache.http.HttpHeaders;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockitoAnnotations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import pro.javatar.security.oidc.utils.TestHelper;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.util.UUID;

@RunWith(SpringRunner.class)
@ContextConfiguration(classes = {
        SpringTestConfig.class,
        AuthenticationJwtBearerTokenAwareFilterTest.SpringConfig.class
})
@WebAppConfiguration
public class AuthenticationJwtBearerTokenAwareFilterTest {

    private final static Logger logger = LoggerFactory.getLogger(AuthenticationOAuth2RedirectAwareFilterTest.class);

    @Autowired
    AuthenticationControllerAdviceFilter authenticationControllerAdviceFilter;

    @Autowired
    AuthenticationRealmAwareFilter authenticationRealmAwareFilter;

    @Autowired
    AuthenticationOAuth2RedirectAwareFilter redirectAwareFilter;

    AuthenticationJwtBearerTokenAwareFilter jwtBearerTokenAwareFilter = new AuthenticationJwtBearerTokenAwareFilter();

    @Autowired
    SecurityTestResource securityTestResource;

    @Autowired
    SecurityTestFilter securityTestFilter;

    @Autowired
    private OidcAuthenticationHelper oidcAuthenticationHelper;

    @Autowired
    private OidcConfiguration oidcConfiguration;

    @Autowired
    private OAuth2AuthorizationFlowService auth2AuthorizationFlowService;

    @Autowired
    private AuthorizationStubFilter authorizationStubFilter;

    @Autowired
    WebApplicationContext wac;

    MockMvc mockMvc;

    ObjectMapper objectMapper = new ObjectMapper();

    @Before
    public void setup() throws ServletException {
        MockitoAnnotations.initMocks(this);

        authenticationRealmAwareFilter.setEnableFilter(true);
        authenticationRealmAwareFilter.setRealmMandatory(true);
        oidcAuthenticationHelper.setOidcConfiguration(oidcConfiguration);
        jwtBearerTokenAwareFilter.setOidcHelper(oidcAuthenticationHelper);
        jwtBearerTokenAwareFilter.setOidcConfiguration(oidcConfiguration);
        jwtBearerTokenAwareFilter.setAuthorizationStubFilter(authorizationStubFilter);
        jwtBearerTokenAwareFilter.init(null);
        this.mockMvc = MockMvcBuilders
                .standaloneSetup(this.securityTestResource)
                .setMessageConverters(new MappingJackson2HttpMessageConverter()) // Important!
                .addFilter(authenticationControllerAdviceFilter, "/*")
                .addFilter(authenticationRealmAwareFilter, "/*")
                .addFilter(redirectAwareFilter, "/*")
                .addFilter(jwtBearerTokenAwareFilter, "/*")
                .addFilter(securityTestFilter, "/*")
                .build();
    }

    @After
    public void tearDown() throws Exception {
        oidcAuthenticationHelper.removeRealmFromCurrentRequest();
        jwtBearerTokenAwareFilter.destroy();
    }

    @Test
    public void jwtBearerFilterEnabled() throws Exception {
        String secureCode = UUID.randomUUID().toString();
        oidcConfiguration.setJwtBearerFilterEnable(true);
        redirectAwareFilter.setEnableFilter(false);
        oidcConfiguration.setFilterApplyUrlRegex(".*");
        securityTestFilter.state = SecurityTestFilter.State.FAIL;
        mockMvc.perform(post("/security/realm/users")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .param("realm", "realm")
                .param(OAuth2Constants.CODE, secureCode)
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(TestHelper.getStub("security-users-test.json")))
                .andDo(print()).andExpect(status().isUnauthorized()).andReturn();
    }

    @Test
    public void isHeaderTokenPresent() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader(eq(HttpHeaders.AUTHORIZATION))).thenReturn("Bearer 2934728937492374");
        assertTrue(jwtBearerTokenAwareFilter.isHeaderTokenPresent(request));

        reset(request);
        when(request.getHeader(eq(HttpHeaders.AUTHORIZATION))).thenReturn("fkddgdg2934728937492374");
        assertTrue(jwtBearerTokenAwareFilter.isHeaderTokenPresent(request));

        reset(request);
        when(request.getHeader(eq(HttpHeaders.AUTHORIZATION))).thenReturn("Digest username=\"admin\", realm=\"Upload gallery\", nonce=\"1497178148607:a209e58eea951d9b028a72306e182960\"");
        assertFalse(jwtBearerTokenAwareFilter.isHeaderTokenPresent(request));

        reset(request);
        when(request.getHeader(eq(HttpHeaders.AUTHORIZATION))).thenReturn("Basic YWRtaW46d3Rxd2VydHk=");
        assertFalse(jwtBearerTokenAwareFilter.isHeaderTokenPresent(request));
    }

    @ComponentScan("pro.javatar.security")
    public static class SpringConfig {

//        @Bean
//        public OAuth2AuthorizationFlowService getOAuth2AuthorizationFlowService(){
//            return mock(OAuth2AuthorizationFlowService.class);
//        }
    }

}