package pro.javatar.security.public_key.api;

import java.util.Map;

public interface RealmPublicKeyCacheService {

    String getPublicKeyByRealm(String realm);

    Map<String, String> getAllPublicKeys();

}
