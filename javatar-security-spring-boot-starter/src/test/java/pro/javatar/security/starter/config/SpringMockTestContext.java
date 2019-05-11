package pro.javatar.security.starter.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import pro.javatar.secret.storage.api.SecretStorageService;

import static org.mockito.Mockito.mock;

/**
 * @author Borys Zora
 * @version 2019-05-11
 */
@Configuration
public class SpringMockTestContext {

    @Bean
    SecretStorageService getSecretStorageService() {
        return mock(SecretStorageService.class);
    }

}
