package pro.javatar.security.public_key.impl;

import pro.javatar.security.public_key.api.RealmPublicKeyCacheService;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Borys Zora
 * @version 2019-06-11
 */
public class RealmPublicKeyCacheServiceInMemoryImmutableImpl implements RealmPublicKeyCacheService {

    private final Map<String, String> keys;

    public RealmPublicKeyCacheServiceInMemoryImmutableImpl(Map<String, String> map) {
        keys = new HashMap<>(map);
    }

    @Override
    public String getPublicKeyByRealm(String realm) {
        return keys.get(realm);
    }

    @Override
    public Map<String, String> getAllPublicKeys() {
        return new HashMap<>(keys);
    }

}
