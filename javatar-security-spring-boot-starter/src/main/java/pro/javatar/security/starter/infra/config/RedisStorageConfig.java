package pro.javatar.security.starter.infra.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import pro.javatar.secret.storage.api.SecretStorageService;
import pro.javatar.security.api.config.SecurityConfig;
import pro.javatar.secret.storage.impl.SecretStorageRedisImpl;
import pro.javatar.security.starter.config.ConfigValidationAware;
import pro.javatar.security.starter.config.ConfigValidationException;

import static pro.javatar.security.oidc.utils.StringUtils.isBlank;

/**
 * @author Serhii Petrychenko
 * @version 2018-04-16
 *
 * @author Borys Zora
 * @version 2019-05-13
 */
@ConditionalOnProperty(value = "javatar.security.token-storage", havingValue = "redis")
@Configuration
public class RedisStorageConfig implements ConfigValidationAware {

    private static final Logger logger = LoggerFactory.getLogger(RedisStorageConfig.class);

    private SecurityConfig.Redis config;

    @Autowired
    public RedisStorageConfig(SecurityConfig config) {
        this.config = config.storage().getRedis();
        validateConfiguration();
    }

    @Override
    public void validateConfiguration() throws ConfigValidationException {
        logger.debug("javatar.security.storage.redis.host={}", config.host());
        logger.debug("javatar.security.storage.redis.port={}", config.port());
        logger.debug("javatar.security.storage.redis.expiration={}", config.expiration());
        logger.debug("javatar.security.storage.redis.password={}", "*******");

        if (isBlank(config.host()) || config.port() == null) { // TODO add config.password();
            throw new ConfigValidationException("redis host & port must be provided");
        }
    }

    @Bean
    public SecretStorageService getSecretStorageRedisImpl() {
        return new SecretStorageRedisImpl(createRedisTemplate(), config.expiration());
    }

    private RedisTemplate createRedisTemplate() {
        JedisConnectionFactory jedisConnectionFactory = createJedisConnectionFactory();
        RedisTemplate redisTemplate = new StringRedisTemplate();
        redisTemplate.setConnectionFactory(jedisConnectionFactory);
        redisTemplate.afterPropertiesSet();
        return redisTemplate;
    }

    private JedisConnectionFactory createJedisConnectionFactory() {
        RedisStandaloneConfiguration redisConfig = new RedisStandaloneConfiguration(config.host(), config.port());
        return new JedisConnectionFactory(redisConfig);
    }

}
