package pro.javatar.security;

import pro.javatar.security.public_key.api.RealmPublicKeyCacheService;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

// TODO in-memory on bean conditional
public class RealmPublicKeyCacheServiceMap implements RealmPublicKeyCacheService {

    private Map<String, String> keys;

    public RealmPublicKeyCacheServiceMap() {
        keys = new ConcurrentHashMap<>();
    }

    @Override
    public String getPublicKeyByRealm(String realm) {
        return keys.get(realm);
    }

    @Override
    public Map<String, String> getAllPublicKeys() {
        return keys;
    }

    public void put(String realm, String publicKey) {
        keys.put(realm, publicKey);
    }
}
