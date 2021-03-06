package pro.javatar.security.oidc.filters;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockitoAnnotations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import pro.javatar.security.api.config.SecurityConfig;
import pro.javatar.security.oidc.SecurityConstants;
import pro.javatar.security.oidc.SecurityTestFilter;
import pro.javatar.security.oidc.SecurityTestResource;
import pro.javatar.security.oidc.services.OidcAuthenticationHelper;
import pro.javatar.security.oidc.services.OidcConfiguration;
import pro.javatar.security.oidc.services.PublicKeyCacheService;
import pro.javatar.security.oidc.utils.SpringTestConfig;
import pro.javatar.security.public_key.api.RealmPublicKeyCacheService;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {SpringTestConfig.class, AuthorizationFlowUsingSecurityFiltersTest.SpringConfig.class})
@WebAppConfiguration
class AuthorizationFlowUsingSecurityFiltersTest {

    private final static Logger logger = LoggerFactory.getLogger(AuthorizationFlowUsingSecurityFiltersTest.class);

    @Autowired
    AuthenticationControllerAdviceFilter authenticationControllerAdviceFilter;

    @Autowired
    AuthenticationRealmAwareFilter authenticationRealmAwareFilter;

    @Autowired
    AuthenticationOAuth2RedirectAwareFilter redirectAwareFilter;

    @Autowired
    AuthenticationJwtBearerTokenAwareFilter jwtBearerTokenAwareFilter;

    @Autowired
    SecurityTestResource securityTestResource;

    @Autowired
    SecurityTestFilter securityTestFilter;

    @Autowired
    AuthorizationStubFilter authorizationStubFilter;

    @Autowired
    OidcAuthenticationHelper oidcAuthenticationHelper;

    @Autowired
    private OidcConfiguration oidcConfiguration;

    @Autowired
    WebApplicationContext wac;

    static RealmPublicKeyCacheService realmPublicKeyCacheService =
            mock(RealmPublicKeyCacheService.class);

    MockMvc mockMvc;

    private String pem;

    @BeforeEach
    void setup() {
        MockitoAnnotations.initMocks(this);
        pem = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAufMhTirSlRD2iQKp6SDheMxSeritq8DeA9ropyua6K//b9D33yQI5vFSfZu4EY/Dj45Vi6XXrc3wK8BC0aMHD8647CABpBGx667KSFmKOWb15DHIYYsvSWS7y5LnZieC5VpNlnqOrSb+8pNbUBJa2VbBRBxnFG6tBzwpZ42Jyo9fFVkwxdBDUiA6GD2Xtf/8v3EboDc7fvtNcrog4/4ICd3/v+aIOVsUTxCTwLkbfdUPHFDetD9vBecWeMouS8Nl4nZO2dG0Im+Z7lcIVu70O8ERkzveULSVgPXqIC0cICqsLKL/VOcfXZ/wcvn0Eb31UuuMVjBsDmqJMXXwypSOWwIDAQAB";
        jwtBearerTokenAwareFilter.setConfig(getConfig());
        oidcAuthenticationHelper.setConfig(getConfig());
        oidcConfiguration.setFilterApplyUrlRegex("\\/.*");
        authenticationRealmAwareFilter.setEnableFilter(true);
        redirectAwareFilter.setEnableFilter(true);
        oidcConfiguration.setJwtBearerFilterEnable(true);
        oidcConfiguration.setCheckIsActive(false);
        oidcConfiguration.setCheckTokenType(false);
        securityTestFilter.state = SecurityTestFilter.State.SKIP;
        authorizationStubFilter.setEnableFilter(false);
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

    @AfterEach
    void tearDown() throws Exception {
        oidcAuthenticationHelper.removeRealmFromCurrentRequest();
    }

    @Test
    void successfullyAuthorizedScenario() throws Exception {
        String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJKV0FVMUFmZ2xCTjRZZDBQdE5ERVpLZWFpNkhhbzBMdVB2aDM5THVCOUswIn0.eyJqdGkiOiJhNWYzMTI4YS03YjU3LTQwYmQtYjBiNi0yZDM3OTIwNjI2ZTciLCJleHAiOjE1MzU2MTYwOTgsIm5iZiI6MCwiaWF0IjoxNTM1NjE1Nzk4LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODkvYXV0aC9yZWFsbXMvZGV2IiwiYXVkIjoiY29uZmlndXJhdGlvbi1zZXJ2aWNlIiwic3ViIjoiNWY0OTI2ZDQtZWQ2NS00Yjg5LTg4MmEtYjk3ODc2NzVmYzg3IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiY29uZmlndXJhdGlvbi1zZXJ2aWNlIiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiMDcwY2ZiMmUtYWE4ZC00NzY3LWE1MTItYWNhM2NiZGE0MmYyIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6W10sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiY29uZmlndXJhdGlvbi1zZXJ2aWNlIjp7InJvbGVzIjpbIlJFQURfREVWX0NPTkZJRyJdfSwiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJwcm9maWxlIGVtYWlsIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJuYW1lIjoiT2xlZyBKZW5raW5zIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiamVua2lucyIsImdpdmVuX25hbWUiOiJPbGVnIiwiZmFtaWx5X25hbWUiOiJKZW5raW5zIiwiZW1haWwiOiJqZW5raW5zQGphdmF0YXIucHJvIn0.pIa__Qi7aIXP_Qh2RuGvBm7OEXdWOOGBwQhQbHrAj854ROW6kKa44_iB-VlnKz5b5ZfYohOETNJM7UFEZbDLwm9R17c2GsTtsqn7RAcaA4IdXaCnCQPaB1xk4kTwBiKedeVMjyvny4Xy7QclJcV7tD8F_tB24vwDtJ0ysQI11yxdjHKM4j-TZ47B8-p6b9jyZbcKfOl0UJhhe6GdEmoXEBqAorjQf5VErdvAk-NwJspMRFXLXmUQmpXyp7OUG3gGDY9GqwCJP93Rv5BIFdkGmAasLWt7KGdztjfqfXWZR7Tf0tnceZKs4gS2ah0Dj8NY6bN-MJMgaNTPhc8TR688jg";
        String refreshToken = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJKV0FVMUFmZ2xCTjRZZDBQdE5ERVpLZWFpNkhhbzBMdVB2aDM5THVCOUswIn0.eyJqdGkiOiJkNmU1NWY0Zi1hZmI1LTQ1NWMtYTYyOC1kNjMwM2Q1ZGFiN2MiLCJleHAiOjE1MzU2MTc1OTgsIm5iZiI6MCwiaWF0IjoxNTM1NjE1Nzk4LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODkvYXV0aC9yZWFsbXMvZGV2IiwiYXVkIjoiY29uZmlndXJhdGlvbi1zZXJ2aWNlIiwic3ViIjoiNWY0OTI2ZDQtZWQ2NS00Yjg5LTg4MmEtYjk3ODc2NzVmYzg3IiwidHlwIjoiUmVmcmVzaCIsImF6cCI6ImNvbmZpZ3VyYXRpb24tc2VydmljZSIsImF1dGhfdGltZSI6MCwic2Vzc2lvbl9zdGF0ZSI6IjA3MGNmYjJlLWFhOGQtNDc2Ny1hNTEyLWFjYTNjYmRhNDJmMiIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiY29uZmlndXJhdGlvbi1zZXJ2aWNlIjp7InJvbGVzIjpbIlJFQURfREVWX0NPTkZJRyJdfSwiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJwcm9maWxlIGVtYWlsIn0.dzt2eXYTboF028kY2J7zZvDNzgY27ds-uV5quBGudzHRY7istVKc_8EavnmGNUHoAraFY67ZKaasAk8WCYP896prDoVpwdSKfPqVqmBp0v3nddEOh2rVXyRfuOH-5c7nhT1y9PgC1ZVPm-fgYIyE5ZkRsQV_-fDt6F02FZxcsxTDBTvm9TS54ZzPT_adTnGlLuUd1CXb5w4p4D6co8cffwlg3TrT3vRWJWLecRv-vw1xvn0-mPLcW91ZafeAd7Net0bfNydh4pgrBjzsfjTDda7TuFCT-6NzWdcKF4BsjHH6SjGoBkSnWZN83eiBxk4U6wyJ8BGvrTFH9HS5r7OkAw";
        when(realmPublicKeyCacheService.getPublicKeyByRealm("dev")).thenReturn(pem);
        mockMvc.perform(get("/security/dev/configs/dev")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .param("realm", "dev")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header(SecurityConstants.REFRESH_TOKEN_HEADER, refreshToken))
                .andDo(print()).andExpect(status().isOk()).andReturn();
    }

    @Test
    void forbiddenScenario() throws Exception {
        String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJKV0FVMUFmZ2xCTjRZZDBQdE5ERVpLZWFpNkhhbzBMdVB2aDM5THVCOUswIn0.eyJqdGkiOiJhNWYzMTI4YS03YjU3LTQwYmQtYjBiNi0yZDM3OTIwNjI2ZTciLCJleHAiOjE1MzU2MTYwOTgsIm5iZiI6MCwiaWF0IjoxNTM1NjE1Nzk4LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODkvYXV0aC9yZWFsbXMvZGV2IiwiYXVkIjoiY29uZmlndXJhdGlvbi1zZXJ2aWNlIiwic3ViIjoiNWY0OTI2ZDQtZWQ2NS00Yjg5LTg4MmEtYjk3ODc2NzVmYzg3IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiY29uZmlndXJhdGlvbi1zZXJ2aWNlIiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiMDcwY2ZiMmUtYWE4ZC00NzY3LWE1MTItYWNhM2NiZGE0MmYyIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6W10sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiY29uZmlndXJhdGlvbi1zZXJ2aWNlIjp7InJvbGVzIjpbIlJFQURfREVWX0NPTkZJRyJdfSwiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJwcm9maWxlIGVtYWlsIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJuYW1lIjoiT2xlZyBKZW5raW5zIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiamVua2lucyIsImdpdmVuX25hbWUiOiJPbGVnIiwiZmFtaWx5X25hbWUiOiJKZW5raW5zIiwiZW1haWwiOiJqZW5raW5zQGphdmF0YXIucHJvIn0.pIa__Qi7aIXP_Qh2RuGvBm7OEXdWOOGBwQhQbHrAj854ROW6kKa44_iB-VlnKz5b5ZfYohOETNJM7UFEZbDLwm9R17c2GsTtsqn7RAcaA4IdXaCnCQPaB1xk4kTwBiKedeVMjyvny4Xy7QclJcV7tD8F_tB24vwDtJ0ysQI11yxdjHKM4j-TZ47B8-p6b9jyZbcKfOl0UJhhe6GdEmoXEBqAorjQf5VErdvAk-NwJspMRFXLXmUQmpXyp7OUG3gGDY9GqwCJP93Rv5BIFdkGmAasLWt7KGdztjfqfXWZR7Tf0tnceZKs4gS2ah0Dj8NY6bN-MJMgaNTPhc8TR688jg";
        String refreshToken = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJKV0FVMUFmZ2xCTjRZZDBQdE5ERVpLZWFpNkhhbzBMdVB2aDM5THVCOUswIn0.eyJqdGkiOiJkNmU1NWY0Zi1hZmI1LTQ1NWMtYTYyOC1kNjMwM2Q1ZGFiN2MiLCJleHAiOjE1MzU2MTc1OTgsIm5iZiI6MCwiaWF0IjoxNTM1NjE1Nzk4LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODkvYXV0aC9yZWFsbXMvZGV2IiwiYXVkIjoiY29uZmlndXJhdGlvbi1zZXJ2aWNlIiwic3ViIjoiNWY0OTI2ZDQtZWQ2NS00Yjg5LTg4MmEtYjk3ODc2NzVmYzg3IiwidHlwIjoiUmVmcmVzaCIsImF6cCI6ImNvbmZpZ3VyYXRpb24tc2VydmljZSIsImF1dGhfdGltZSI6MCwic2Vzc2lvbl9zdGF0ZSI6IjA3MGNmYjJlLWFhOGQtNDc2Ny1hNTEyLWFjYTNjYmRhNDJmMiIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiY29uZmlndXJhdGlvbi1zZXJ2aWNlIjp7InJvbGVzIjpbIlJFQURfREVWX0NPTkZJRyJdfSwiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJwcm9maWxlIGVtYWlsIn0.dzt2eXYTboF028kY2J7zZvDNzgY27ds-uV5quBGudzHRY7istVKc_8EavnmGNUHoAraFY67ZKaasAk8WCYP896prDoVpwdSKfPqVqmBp0v3nddEOh2rVXyRfuOH-5c7nhT1y9PgC1ZVPm-fgYIyE5ZkRsQV_-fDt6F02FZxcsxTDBTvm9TS54ZzPT_adTnGlLuUd1CXb5w4p4D6co8cffwlg3TrT3vRWJWLecRv-vw1xvn0-mPLcW91ZafeAd7Net0bfNydh4pgrBjzsfjTDda7TuFCT-6NzWdcKF4BsjHH6SjGoBkSnWZN83eiBxk4U6wyJ8BGvrTFH9HS5r7OkAw";
        when(realmPublicKeyCacheService.getPublicKeyByRealm("dev")).thenReturn(pem);
        mockMvc.perform(get("/security/dev/configs/qa")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .param("realm", "dev")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header(HttpHeaders.AUTHORIZATION, refreshToken))
                .andDo(print()).andExpect(status().isForbidden()).andReturn();
    }

    private String getStub(String classpathFile) throws Exception {
        return new String(Files.readAllBytes(Paths.get(getClass().getClassLoader().getResource(classpathFile).toURI())));
    }

    @Configuration
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    @ComponentScan("pro.javatar.security")
    public static class SpringConfig {

        @Autowired
        public void registerGlobal(AuthenticationManagerBuilder auth) throws Exception {
            auth
                    .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER").and()
                    .withUser("admin").password("password").roles("USER", "ADMIN");
        }

        @Autowired
        public void setPublicKeyCacheService(PublicKeyCacheService publicKeyCacheService) {
            publicKeyCacheService.setRealmPublicKeyCacheService(
                    AuthorizationFlowUsingSecurityFiltersTest.realmPublicKeyCacheService);
        }

    }

    // TODO replace with mock
    public SecurityConfig getConfig() {
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
                return new IdentityProvider() {
                    @Override
                    public String url() {
                        return null;
                    }

                    @Override
                    public String client() {
                        return "configuration-service";
                    }

                    @Override
                    public String secret() {
                        return null;
                    }

                    @Override
                    public String realm() {
                        return "dev";
                    }
                };
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
                return new TokenValidation() {
                    @Override
                    public Boolean checkTokenIsActive() {
                        return false;
                    }

                    @Override
                    public Boolean skipRefererCheck() {
                        return true;
                    }

                    @Override
                    public Boolean checkTokenType() {
                        return true;
                    }

                    @Override
                    public Boolean realmRequired() {
                        return true;
                    }
                };
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