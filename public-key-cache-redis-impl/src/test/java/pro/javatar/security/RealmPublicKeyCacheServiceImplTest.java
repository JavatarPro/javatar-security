package pro.javatar.security;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import redis.embedded.RedisServer;

import java.util.Map;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {RealmPublicKeyCacheServiceImplTest.SpringConfig.class})
public class RealmPublicKeyCacheServiceImplTest {
    private static final Logger LOG = LoggerFactory.getLogger(RealmPublicKeyCacheServiceImplTest.class);
    private static final String SOME_REALM = "SOME_REALM";
    private static final int REDIS_PORT = 6399;

    RedisServer redisServer;

    private RealmPublicKeyCacheServiceImpl publicKeyCacheService;

    private String keyPattern = "security.public.key.for.realm.";
    private String datPublicKey;

    @Before
    public void setUp() throws Exception {
        datPublicKey = "public_key_131283618263123";
        LOG.info("set up redis server");
//        redisServer = new RedisServerBuilder().setting("maxheap 256Mb").port(REDIS_PORT).build();
        redisServer = new RedisServer(REDIS_PORT);
        redisServer.start();

        RealmPublicKeyCacheConfiguration configuration = new RealmPublicKeyCacheConfiguration();
        configuration.setHost("localhost");
        configuration.setPort(REDIS_PORT);
        configuration.setUsePool(true);
        RedisTemplate redisTemplate = configuration.createRedisTemplate();

        publicKeyCacheService = new RealmPublicKeyCacheServiceExt(keyPattern, redisTemplate);
        publicKeyCacheService.put(keyPattern + SOME_REALM, datPublicKey);
        publicKeyCacheService.put(keyPattern + "REALM", "realm_public_key_3234789237942934");
        publicKeyCacheService.put(keyPattern + "REALM_SK", "realm_sk_public_key_93878745345");
    }

    @After
    public void tearDown() throws Exception {
        LOG.info("stop redis server");
        redisServer.stop();
        LOG.info("test completed");
    }

    @Test
    public void getPublicKeyByRealm() throws Exception {
        String actualPublicKey = publicKeyCacheService.getPublicKeyByRealm(SOME_REALM);
        assertThat(actualPublicKey, is(datPublicKey));
    }

    @Test
    public void tryGetNonExistingKey() throws Exception {
        String actualPublicKey = publicKeyCacheService.getPublicKeyByRealm("notExistedKey");
        assertThat(actualPublicKey, is(nullValue()));
    }

    @Test
    public void getAllPublicKeys() throws Exception {
        Map<String, String> allPublicKeys = publicKeyCacheService.getAllPublicKeys();
        assertThat(3, is(allPublicKeys.size()));
        assertThat(allPublicKeys.get(SOME_REALM), is(datPublicKey));
        assertThat(allPublicKeys.containsKey("REALM"), is(true));
        assertThat(allPublicKeys.containsKey("REALM_SK"), is(true));
    }

    @Test
    public void generateKey() throws Exception {
        String actualKey = publicKeyCacheService.generateKey(SOME_REALM);
        assertThat(actualKey, is(keyPattern + SOME_REALM));
    }

    @ComponentScan("pro.javatar.security")
    public static class SpringConfig {
    }

    private static class RealmPublicKeyCacheServiceExt extends RealmPublicKeyCacheServiceImpl {

        private RedisTemplate<String, String> redisTemplate;

        public RealmPublicKeyCacheServiceExt(String keyPattern, RedisTemplate<String, String> redisTemplate) {
            super(keyPattern, redisTemplate);
            this.redisTemplate = redisTemplate;
        }

        @Override
        public void put(String key, String value) {
            redisTemplate.opsForValue().set(key, value);
        }
    }
}