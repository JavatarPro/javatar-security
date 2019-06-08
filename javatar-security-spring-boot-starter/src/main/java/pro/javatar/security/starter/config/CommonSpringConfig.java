package pro.javatar.security.starter.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import pro.javatar.security.api.AuthService;
import pro.javatar.security.api.config.SecurityConfig;
import pro.javatar.security.impl.AuthServiceImpl;
import pro.javatar.security.impl.coverter.AuthBOConverter;
import pro.javatar.security.oidc.client.OAuthClient;
import pro.javatar.security.oidc.filters.AuthorizationStubFilter;
import pro.javatar.security.oidc.services.OidcAuthenticationHelper;
import pro.javatar.security.oidc.services.api.RealmService;
import pro.javatar.security.oidc.services.impl.RealmServiceImpl;
import pro.javatar.security.oidc.utils.JsonMessageBuilder;

/**
 * @author Borys Zora
 * @version 2019-05-19
 */
@Configuration
public class CommonSpringConfig {

    @Autowired
    private SecurityConfig securityConfig;

    @Autowired
    private OAuthClient oAuthClient;

    @Autowired
    private AuthBOConverter authBOConverter;

    @Bean
    public JsonMessageBuilder messageBuilder() {
        return new JsonMessageBuilder(securityConfig.errorDescriptionLink());
    }

    @Bean
    public RealmService realmService() {
        return new RealmServiceImpl(securityConfig);
    }

    public OidcAuthenticationHelper oidcAuthenticationHelper() {
        return new OidcAuthenticationHelper();
    }

    @Bean
    public AuthorizationStubFilter authorizationStubFilter() {
        return new AuthorizationStubFilter(oidcAuthenticationHelper(), securityConfig);
    }

    @Bean
    public AuthService authService() {
        return new AuthServiceImpl(oAuthClient, authBOConverter);
    }
}
