package pro.javatar.security.api;

import pro.javatar.security.api.model.User;

/**
 * Main interface to Javatar security, any runtime information could be accessed from it.
 * Every user could inject/autowire this interface and access to security information
 *
 * @author Borys Zora
 * @version 2019-04-21
 */
public interface SecurityService {

    User getCurrentUser();

    String getCurrentUserId();

    String getCurrentRealm();

    String getCurrentLogin();

}
