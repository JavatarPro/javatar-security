package pro.javatar.security.starter.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import pro.javatar.security.api.config.SecurityConfig;
import pro.javatar.security.impl.config.JavatarSecurityFilterConfiguration;
import pro.javatar.security.public_key.api.RealmPublicKeyCacheService;
import pro.javatar.security.public_key.impl.RealmPublicKeyCacheServiceInMemoryImmutableImpl;

/**
 * @author Borys Zora
 * @version 2019-05-19
 */
@Configuration
@Import(value = {
        JavatarSecurityFilterConfiguration.class,
        JavatarSecurityFilterOrderConfiguration.class
})
public class JavatarSecurityFilterBootConfiguration {

    @Autowired
    SecurityConfig securityConfig;

    @ConditionalOnProperty(value = "javatar.security.public-keys-storage", havingValue = "in-memory")
    @Bean
    public RealmPublicKeyCacheService realmPublicKeyCacheService() {
        return new RealmPublicKeyCacheServiceInMemoryImmutableImpl(securityConfig.storage().getInMemory().publicKeys());
    }

}
