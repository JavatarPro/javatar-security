package pro.javatar.security.oidc.services;

import pro.javatar.security.public_key.api.RealmPublicKeyCacheService;
import pro.javatar.security.oidc.exceptions.PublicKeyNotFoundAuthenticationException;
import pro.javatar.security.oidc.utils.StringUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class PublicKeyCacheService {
    private static final Logger logger = LoggerFactory.getLogger(PublicKeyCacheService.class);

    private Map<String, String> publicKeys = new ConcurrentHashMap<>();

    private RealmPublicKeyCacheService realmPublicKeyCacheService;

    @Autowired
    public PublicKeyCacheService(RealmPublicKeyCacheService realmPublicKeyCacheService) {
        this.realmPublicKeyCacheService = realmPublicKeyCacheService;
    }

    /**
     * @param realm incoming realm
     * @return public key by specified realm
     */
    public String getPublicKeyByRealm(String realm) {
        if (publicKeys.containsKey(realm)) {
            return publicKeys.get(realm);
        } else {
            logger.debug("Refresh public key for realm {}", realm);
            return refreshPublicKey(realm);
        }
    }

    /**
     * Obtains public key by specified realm from database.
     *
     * @param realm incoming realm
     * @return refreshed public key by specified realm
     */
    public String refreshPublicKey(String realm) {
        String publicKey = realmPublicKeyCacheService.getPublicKeyByRealm(realm);
        if (StringUtils.isBlank(publicKey)) {
            logger.error("Public key for realm {} is not found.");
            throw new PublicKeyNotFoundAuthenticationException();
        }
        publicKeys.put(realm, publicKey);
        return publicKey;
    }

    public void setRealmPublicKeyCacheService(RealmPublicKeyCacheService realmPublicKeyCacheService) {
        this.realmPublicKeyCacheService = realmPublicKeyCacheService;
    }

    @PostConstruct
    private void initPublicKeys() {
        try {
            Map<String, String> allPublicKeys = realmPublicKeyCacheService.getAllPublicKeys();
            if (allPublicKeys != null) {
                publicKeys = allPublicKeys;
            }
        } catch (Exception e) {
            logger.error("Public keys initialization cache error.", e);
        }
    }
}