package pro.javatar.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class RealmPublicKeyCacheServiceImpl implements RealmPublicKeyCacheService {
    private static final Logger logger = LoggerFactory.getLogger(RealmPublicKeyCacheServiceImpl.class);

    private String keyPattern;

    private RedisTemplate<String,String> redisTemplate;

    public RealmPublicKeyCacheServiceImpl(String keyPattern, RedisTemplate<String, String> redisTemplate) {
        this.keyPattern = keyPattern;
        this.redisTemplate = redisTemplate;
    }

    public void put(String key, String value) {
        throw new UnsupportedOperationException("Put method does not supported");
    }

    @Override
    public String getPublicKeyByRealm(String realm) {
        String key = generateKey(realm);
        logger.info("Trying to get public key for realm `{}`", key);
        return redisTemplate.opsForValue().get(key);
    }

    String generateKey(String realm) {
        return keyPattern + realm;
    }

    @Override
    public Map<String, String> getAllPublicKeys() {
        String pattern = keyPattern + "*";
        logger.info("Trying to load public keys by pattern `{}`", pattern);
        Collection<String> keys = redisTemplate.keys(pattern);
        ConcurrentHashMap<String, String> map = new ConcurrentHashMap<>(keys.size());
        for (String key : keys) {
            String pk = redisTemplate.opsForValue().get(key);
            logger.debug("Key={}, Value={}", key, pk);
            map.put(key.replace(keyPattern, ""), pk);
        }
        logger.info("{} public keys were founded", map.size());
        return map;
    }
}