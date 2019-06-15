package pro.javatar.secret.storage.api;

import pro.javatar.secret.storage.api.exception.DeleteFailedSecretStorageException;
import pro.javatar.secret.storage.api.exception.PersistenceSecretStorageException;
import pro.javatar.secret.storage.api.exception.TokenNotFoundSecretStorageException;
import pro.javatar.secret.storage.api.model.SecretTokenDetails;

public interface SecretStorageService {

    void put(String secretKey, SecretTokenDetails secretTokenDetails) throws PersistenceSecretStorageException;

    SecretTokenDetails get(String secretKey) throws TokenNotFoundSecretStorageException;

    void delete(String secretKey) throws DeleteFailedSecretStorageException;

}
