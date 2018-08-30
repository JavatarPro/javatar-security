package pro.javatar.security.oidc.services;

import pro.javatar.security.oidc.model.UserKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import pro.javatar.security.oidc.utils.StringUtils;

import static pro.javatar.security.oidc.utils.StringUtils.isNotBlank;

@Service
public class OnBehalfOfUsernameHolder {

    private static final Logger logger = LoggerFactory.getLogger(OnBehalfOfUsernameHolder.class);

    private final ThreadLocal<UserKey> user = new ThreadLocal<>();

    public UserKey getUser() {
        return user.get();
    }

    public void putUser(String username, String realm) {
        if (StringUtils.isNotBlank(username) && StringUtils.isNotBlank(realm)) {
            UserKey user = new UserKey(username, realm);
            this.user.set(user);
            logger.info("on behalf user: {} was set", user);
        } else {
            this.user.set(null);
            logger.info("on behalf user is empty null was set");
        }
    }

    public void putUser(UserKey user) {
        logger.info("on behalf user: {} was set", user);
        this.user.set(user);
    }

    public void removeUser() {
        user.remove();
    }
}
