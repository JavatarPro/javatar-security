package pro.javatar.security.oidc.utils;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import pro.javatar.security.RealmPublicKeyCacheService;
import pro.javatar.security.RealmPublicKeyCacheServiceMap;
import pro.javatar.security.api.config.SecurityConfig;
import pro.javatar.security.oidc.filters.AuthorizationStubFilter;
import pro.javatar.security.oidc.services.OidcAuthenticationHelper;
import pro.javatar.security.oidc.services.api.RealmService;
import pro.javatar.security.oidc.services.impl.RealmServiceImpl;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Borys Zora
 * @version 2019-05-18
 */
@Configuration
public class SpringTestConfig {

    @Bean
    public JsonMessageBuilder messageBuilder() {
        return new JsonMessageBuilder("http://jira.javatar.pro/confluence/x/TgZmAQ");
    }

    @Bean
    public AuthorizationStubFilter authorizationStubFilter(OidcAuthenticationHelper oidcHelper) {
        return new AuthorizationStubFilter(oidcHelper, securityConfig());
    }

    @Bean
    public RealmPublicKeyCacheService  realmPublicKeyCacheService() {
        if ("in-memory".equalsIgnoreCase(securityConfig().publicKeysStorage())) {
            RealmPublicKeyCacheService result = new RealmPublicKeyCacheServiceMap();
            Map<String, String> map = securityConfig().storage().getInMemory().publicKeys();
            map.forEach(result::put);
            return result;
        }
        return null;
    }

    @Bean
    public RealmService realmService() {
        return new RealmServiceImpl(securityConfig());
    }

    @Bean
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
            public String redirectUrl() {
                return null;
            }

            @Override
            public IdentityProvider identityProvider() {
                return new IdentityProvider() {
                    @Override
                    public String url() {
                        return "http://195.201.110.123:48666";
                    }

                    @Override
                    public String client() {
                        return "user-management-service";
                    }

                    @Override
                    public String secret() {
                        return "86ff8f97-04b5-43f0-9c2f-6031d4e11aac";
                    }

                    @Override
                    public String realm() {
                        return "javatar-security";
                    }
                };
            }

            @Override
            public Boolean useReferAsRedirectUri() {
                return null;
            }

            @Override
            public String publicKeysStorage() {
                return "in-memory";
            }

            @Override
            public String tokenStorage() {
                return null;
            }

            @Override
            public Storage storage() {
                return new Storage() {
                    @Override
                    public Redis getRedis() {
                        return null;
                    }

                    @Override
                    public InMemory getInMemory() {
                        return () -> {
                            Map<String, String> map = new HashMap<>();
                            map.put("javatar-security", "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0zu4hSUMSsAMQIO/5cun3XPDvHeKmpYuZb5ylzP0JGsvwQIKzf232LAkdOjn8brUtLxLE7R2zramGH+EYiObuKloaGAxgUTyu0wfi2BbZ5junaE56ge69UrGPTePQ0K6w3nWItOFerjEOi0k4kcSAbMof3tot4bp9J5CG/7eFGMBPY1Ru2DdTC8dN9Ipbq6EbvbM5n1mOOz+UkGuFvCozFhJv3wrLVvgOCC4TelZXFClJRzQUddC67GYufmlbd5G6K6qxPwI6ztvZEwGGKp94MukoWsR19xeUdKud2W4GUvHicnNwwIwSOxeIgNqPrXXsFKzSY8TT8mrs1hZRgIPsQIDAQAB");
                            return map;
                        };
                    }

                    @Override
                    public Vault getVault() {
                        return null;
                    }
                };
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
                return new Stub() {
                    @Override
                    public Boolean enabled() {
                        return true;
                    }

                    @Override
                    public String accessToken() {
                        return "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ2S0RkVV83VXNqeFFWSWJIZ1E3aGZvS2EtRDBuQWs5MFFYejI4dm0zYnRjIn0.eyJqdGkiOiJiNjlmMjhkZi0yOWZlLTQwZDctOTA5Ny0xOTM4OTA3ZWNlNDMiLCJleHAiOjE1NTgzMDE4ODksIm5iZiI6MCwiaWF0IjoxNTU4MzAxNTg5LCJpc3MiOiJodHRwOi8vMTk1LjIwMS4xMTAuMTIzOjQ4NjY2L2F1dGgvcmVhbG1zL2phdmF0YXItc2VjdXJpdHkiLCJhdWQiOiJ1c2VyLW1hbmFnZW1lbnQtc2VydmljZSIsInN1YiI6Ijk1MDNmYmVkLTc5ZTMtNGFmMi04ZTNkLTM4ODBhZjUzOWFjMCIsInR5cCI6IkJlYXJlciIsImF6cCI6InVzZXItbWFuYWdlbWVudC1zZXJ2aWNlIiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiM2VlNzNjMDUtYzI0Yy00ZWEwLWE4YTQtNjQ2YmQ2MzE2NDU5IiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6W10sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsidXNlci1tYW5hZ2VtZW50LXNlcnZpY2UiOnsicm9sZXMiOlsiVVNFUl9XUklURSIsIlVTRVJfUkVBRCJdfSwiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJuYW1lIjoiT2xlZyBKZW5raW5zIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiamVua2lucyIsImdpdmVuX25hbWUiOiJPbGVnIiwiZmFtaWx5X25hbWUiOiJKZW5raW5zIiwiZW1haWwiOiJqZW5raW5zQGphdmF0YXIucHJvIn0.0gVGqPvqJ3pm8JNMxebzN-lwFP-3cRpuxoYces2RlK4OC44FQK3bMIUQpyWLUSIFVANbRtVOWFDjnOeAO_X5JWXiRXCQkrr4mHmpLPzG3R-ozQoK5v08RBjxNaDYlSxIupKV5ZfvynVVArvaMwFHay-zONYIX-EA4K7ZEfhZX1XIIYbLe4T2aCZwFP62d9dqJLBD7zmj7Exygs39Rl6FHKbhTgmdDzr1XuCnLJZ9dpd8G74-N6zNdZMPBAJbmcjYpzlALVLHJ2mUUTivL8yQS6uIfCV9YvxWTNmND_-F0hvg3mDVw2PdefBWdhB5GkC92RZDtGCxU-Dmoaq-1c9vzw";
                    }
                };
            }

            @Override
            public HttpClient httpClient() {
                return null;
            }

            @Override
            public Application application() {
                return new Application() {
                    @Override
                    public String user() {
                        return "jenkins";
                    }

                    @Override
                    public String password() {
                        return "se(ur3";
                    }

                    @Override
                    public Duration tokenShouldBeRefreshedDuration() {
                        return null;
                    }

                    @Override
                    public Boolean allowOtherAuthentication() {
                        return null;
                    }

                    @Override
                    public Boolean allowAnonymous() {
                        return null;
                    }

                    @Override
                    public Realm realm() {
                        return null;
                    }
                };
            }

            @Override
            public String errorDescriptionLink() {
                return null;
            }
        };
    }
}
