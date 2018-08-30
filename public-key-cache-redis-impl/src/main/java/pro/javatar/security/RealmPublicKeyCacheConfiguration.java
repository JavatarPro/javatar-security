package pro.javatar.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;

@Configuration
public class RealmPublicKeyCacheConfiguration implements InitializingBean {
    private static final Logger logger = LoggerFactory.getLogger(RealmPublicKeyCacheConfiguration.class);

    private String host;
    private Integer port;
    private Boolean usePool;
    private String keyPattern;
    private boolean isEnabled;

    @Value("${security.realm.cache.host:localhost}")
    public void setHost(String host) {
        this.host = host;
    }

    @Value("${security.realm.cache.port:6379}")
    public void setPort(Integer port) {
        this.port = port;
    }

    @Value("${security.realm.cache.usePool:true}")
    public void setUsePool(Boolean usePool) {
        this.usePool = usePool;
    }

    @Value("${security.realm.cache.keyPattern:security.public.key.for.realm.}")
    public void setKeyPattern(String keyPattern) {
        this.keyPattern = keyPattern;
    }

    @Value("${security.realm.cache.enable:true}")
    public void setEnabled(boolean enabled) {
        isEnabled = enabled;
    }

    @Bean
    public RealmPublicKeyCacheService getPublicKeyCacheServiceImpl() {
        logger.debug("security.realm.cache.enable={}", isEnabled);
        logger.debug("security.realm.cache.keyPattern={}", keyPattern);

        if (!isEnabled) {
            return new RealmPublicKeyCacheServiceMap();
        }

        logger.debug("security.realm.cache.host={}", host);
        logger.debug("security.realm.cache.port={}", port);
        logger.debug("security.realm.cache.usePool={}", usePool);

        return new RealmPublicKeyCacheServiceImpl(keyPattern, createRedisTemplate());
    }

    RedisTemplate createRedisTemplate() {
        JedisConnectionFactory jedisConnectionFactory = createJedisConnectionFactory();
        RedisTemplate redisTemplate = new StringRedisTemplate();
        redisTemplate.setConnectionFactory(jedisConnectionFactory);
        redisTemplate.afterPropertiesSet();
        return redisTemplate;
    }

    private JedisConnectionFactory createJedisConnectionFactory() {
        JedisConnectionFactory jedisConnectionFactory = new JedisConnectionFactory();
        jedisConnectionFactory.setHostName(host);
        jedisConnectionFactory.setPort(port);
        jedisConnectionFactory.setUsePool(usePool);
        jedisConnectionFactory.afterPropertiesSet();
        return jedisConnectionFactory;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        if (logger.isDebugEnabled()) {
            logger.debug(this.toString());
        }
    }

    @Override
    public String toString() {
        return "Cache Configuration: {" +
                "host='" + host + '\'' +
                ", port=" + port +
                ", usePool=" + usePool +
                ", keyPattern='" + keyPattern + '\'' +
                ", isEnabled=" + isEnabled +
                '}';
    }
}
