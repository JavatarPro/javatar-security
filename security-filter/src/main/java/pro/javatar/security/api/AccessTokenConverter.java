package pro.javatar.security.api;

import pro.javatar.security.api.model.TokenExpirationInfoBO;
import pro.javatar.security.api.model.User;

/**
 * @author Borys Zora
 * @version 2019-07-22
 */
public interface AccessTokenConverter {

    TokenExpirationInfoBO toTokenExpirationInfoBO(String accessToken);

    User toUserFromAccessToken(String accessToken);

}
