package pro.javatar.security.gateway.resources;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import pro.javatar.security.api.AuthService;
import pro.javatar.security.gateway.config.GatewaySpringConfig;

import static org.mockito.Mockito.mock;

/**
 * @author Borys Zora
 * @version 2019-06-02
 */
@Configuration
@Import(GatewaySpringConfig.class)
public class SpringTestConfig {

    @Bean
    AuthService authService() {
        return mock(AuthService.class);
    }

}
