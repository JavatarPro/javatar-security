package pro.javatar.security;

import java.util.Map;

public interface RealmPublicKeyCacheService {

    String getPublicKeyByRealm(String realm);

    Map<String, String> getAllPublicKeys();

    void put(String realm, String publicKey);

}
