package pro.javatar.secret.storage.api.exception;

/**
 * @author Borys Zora
 * @version 2019-06-15
 */
public class TokenNotFoundSecretStorageException extends SecretStorageException {

    public TokenNotFoundSecretStorageException(String message) {
        super(message);
    }
}
