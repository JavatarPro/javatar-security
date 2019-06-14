package pro.javatar.security.starter.config.model;

import pro.javatar.security.api.config.SecurityConfig;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Borys Zora
 * @version 2019-06-14
 */
public class InMemoryStorage implements SecurityConfig.InMemory {

    HashMap<String, String> publicKeys = new HashMap<>();

    @Override
    public Map<String, String> publicKeys() {
        return publicKeys;
    }

    public void setPublicKeys(HashMap<String, String> publicKeys) {
        this.publicKeys = publicKeys;
    }

    @Override
    public String toString() {
        return "InMemoryStorage{" +
                "publicKeys=" + publicKeys +
                '}';
    }
}