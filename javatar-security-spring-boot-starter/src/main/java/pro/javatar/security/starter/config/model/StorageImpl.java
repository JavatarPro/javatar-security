package pro.javatar.security.starter.config.model;

import pro.javatar.security.api.config.SecurityConfig;

/**
 * @author Borys Zora
 * @version 2019-06-14
 */
public class StorageImpl implements SecurityConfig.Storage {

    RedisStorage redis;

    InMemoryStorage inMemory;

    VaultStorage vault;

    @Override
    public SecurityConfig.Redis getRedis() {
        return redis;
    }

    @Override
    public SecurityConfig.InMemory getInMemory() {
        return inMemory;
    }

    @Override
    public SecurityConfig.Vault getVault() {
        return vault;
    }

    public void setRedis(RedisStorage redis) {
        this.redis = redis;
    }

    public void setInMemory(InMemoryStorage inMemory) {
        this.inMemory = inMemory;
    }

    public void setVault(VaultStorage vault) {
        this.vault = vault;
    }

    @Override
    public String toString() {
        return "StorageImpl{" +
                "redis=" + redis +
                ", inMemory=" + inMemory +
                ", vault=" + vault +
                '}';
    }
}