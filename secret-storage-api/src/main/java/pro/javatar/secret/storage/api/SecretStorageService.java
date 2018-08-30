package pro.javatar.secret.storage.api;

import pro.javatar.secret.storage.api.model.SecretTokenDetails;

public interface SecretStorageService {

    void put(String secretKey, SecretTokenDetails secretTokenDetails);

    SecretTokenDetails get(String secretKey);

    void delete(String secretKey);

    String getStorageName();
}
