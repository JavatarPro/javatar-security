package pro.javatar.security;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

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

    @Override
    public void put(String realm, String publicKey) {
        keys.put(realm, publicKey);
    }
}
