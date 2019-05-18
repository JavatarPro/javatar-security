package pro.javatar.security.starter.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import pro.javatar.security.api.config.SecurityConfig;
import pro.javatar.security.oidc.utils.JsonMessageBuilder;

/**
 * @author Borys Zora
 * @version 2019-05-19
 */
@Configuration
public class CommonSpringConfig {

    private SecurityConfig securityConfig;

    @Autowired
    public CommonSpringConfig(SecurityConfig securityConfig) {
        this.securityConfig = securityConfig;
    }

    @Bean
    public JsonMessageBuilder messageBuilder() {
        return new JsonMessageBuilder(securityConfig.errorDescriptionLink());
    }

}
