package pro.javatar.security.api;

import pro.javatar.security.api.model.User;

/**
 * @author Borys Zora
 * @version 2019-04-21
 */
public interface SecurityService {

    User getCurrentUser();

    String getCurrentUserId();

    String getCurrentRealm();

    String getCurrentLogin();

}
