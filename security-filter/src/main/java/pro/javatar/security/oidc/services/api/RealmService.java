package pro.javatar.security.oidc.services.api;

import pro.javatar.security.oidc.exceptions.RealmInJwtTokenNotFoundAuthenticationException;
import pro.javatar.security.oidc.exceptions.TokenSignedForOtherRealmAuthorizationException;
import pro.javatar.security.oidc.model.TokenDetails;

import javax.servlet.http.HttpServletResponse;

/**
 * @author Borys Zora
 * @version 2019-05-25
 */
public interface RealmService {

    void setRealmForCurrentRequest(String realm);

    String getRealmForCurrentRequest();

    // TODO name is confusing, get from request but parameter passed response
    String getRealmForCurrentRequest(HttpServletResponse response);

    void validateRealm(TokenDetails tokenDetails) throws TokenSignedForOtherRealmAuthorizationException;

    void removeRealmFromCurrentRequest();

    String getRealmFromToken(String accessToken) throws RealmInJwtTokenNotFoundAuthenticationException;

}
