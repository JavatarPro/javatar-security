package pro.javatar.security.oidc.converter;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import pro.javatar.security.jwt.utils.Base64Url;
import pro.javatar.security.api.model.User;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static pro.javatar.security.oidc.utils.StringUtils.isBlank;

/**
 * @author Borys Zora
 * @version 2019-04-21
 */
@Service
public class UserConverter {

    private static final Logger logger = LoggerFactory.getLogger(UserConverter.class);

    private ObjectMapper objectMapper = new ObjectMapper();

    public User toUserFromAccessToken(String accessToken) {
        try {
            String userInfoPart = retrieveUserInfoPart(accessToken);
            if (userInfoPart == null) {
                return null;
            }
            Map token = objectMapper.readValue(userInfoPart, HashMap.class);
            return toUserFromAccessTokenMap(token);
        } catch (IOException e) {
            logger.error("Could not convert user from access token: {}, {}", accessToken, e.getMessage(), e);
            return null;
        }
    }

    public User toUserFromAccessTokenMap(Map<String, Object> accessTokenMap) {
        User user = new User();
        user.setId((String) accessTokenMap.get("sub"));
        user.setName((String) accessTokenMap.get("name"));
        user.setGivenName((String) accessTokenMap.get("given_name"));
        user.setFamilyName((String) accessTokenMap.get("family_name"));
        user.setPreferredUsername((String) accessTokenMap.get("preferred_username"));
        user.setEmail((String) accessTokenMap.get("email"));
        user.setScope((String) accessTokenMap.get("scope"));
        user.setEmailVerified((Boolean) accessTokenMap.get("email_verified"));
        return user;
    }

    String retrieveUserInfoPart(String accessToken) {
        if (isBlank(accessToken)) {
            logger.error("token is not valid it is null");
            return null;
        }
        String[] parts = accessToken.split("\\.");
        if (parts.length < 2) {
            logger.error("token is not valid it contains only {} parts {}", parts.length);
            return null;
        }
        return new String(Base64Url.decode(parts[1]));
    }
}
