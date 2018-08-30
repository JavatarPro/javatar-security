package pro.javatar.security.oidc.services;

import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.model.UserKey;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class ApplicationTokenHolder {

    private Map<UserKey, TokenDetails> tokenDetailsMap = new ConcurrentHashMap<>();

    public TokenDetails getTokenDetails(UserKey user) {
        return tokenDetailsMap.get(user);
    }

    public void setTokenDetails(UserKey user, TokenDetails tokenDetails) {
        tokenDetailsMap.put(user, tokenDetails);
    }
}
