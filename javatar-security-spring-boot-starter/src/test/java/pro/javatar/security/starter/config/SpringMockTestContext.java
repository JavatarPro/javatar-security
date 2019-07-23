package pro.javatar.security.starter.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import pro.javatar.secret.storage.api.SecretStorage;

import static org.mockito.Mockito.mock;

/**
 * @author Borys Zora
 * @version 2019-05-11
 */
@Configuration
public class SpringMockTestContext {

    @Primary
    @Bean
    SecretStorage getSecretStorageService() {
        return mock(SecretStorage.class);
    }

}
