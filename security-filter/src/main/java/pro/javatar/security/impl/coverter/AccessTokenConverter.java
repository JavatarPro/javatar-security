package pro.javatar.security.impl.coverter;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import pro.javatar.security.api.model.TokenExpirationInfoBO;
import pro.javatar.security.jwt.utils.Base64Url;
import pro.javatar.security.api.model.User;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static pro.javatar.security.oidc.utils.StringUtils.isBlank;

/**
 * jwt access token consist of 3 parts:
 *  - header (e.g. algorithm and token type)
 *  - payload (user data, expiration info)
 *  - signature
 * The aim of this class to retrieve payload related data from raw access token
 *
 * @author Borys Zora
 * @version 2019-04-21
 */
@Service
public class AccessTokenConverter implements pro.javatar.security.api.AccessTokenConverter {

    private static final Logger logger = LoggerFactory.getLogger(AccessTokenConverter.class);

    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public TokenExpirationInfoBO toTokenExpirationInfoBO(String accessToken) {
        Map token = convertPayloadPartToMap(accessToken);
        return toTokenExpirationInfoBO(token);
    }

    // TODO retrieve realm
    @Override
    public User toUserFromAccessToken(String accessToken) {
        Map token = convertPayloadPartToMap(accessToken);
        return toUserFromAccessTokenMap(token);
    }

    private TokenExpirationInfoBO toTokenExpirationInfoBO(Map<String, Object> accessTokenMap) {
        if (accessTokenMap == null || accessTokenMap.isEmpty()) {
            return new TokenExpirationInfoBO();
        }

        int issuedAt = (Integer) accessTokenMap.get("iat");
        int expiration = (Integer) accessTokenMap.get("exp");

        return new TokenExpirationInfoBO(issuedAt, expiration);
    }

    // TODO Read json as object, ignore missing values
    // TODO (bzo, amur) move/reuse jwt-lib or vise versa, use not that heavy token that used for generating jwt
    private User toUserFromAccessTokenMap(Map<String, Object> accessTokenMap) {
        User user = new User();
        if (accessTokenMap == null || accessTokenMap.isEmpty()) {
            return user;
        }
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

    private String retrievePayloadPart(String accessToken) {
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

    private Map<String, Object> convertPayloadPartToMap(String accessToken) {
        try {
            String userInfoPart = retrievePayloadPart(accessToken);
            if (userInfoPart == null) {
                return null;
            }
            return objectMapper.readValue(userInfoPart, HashMap.class);
        } catch (IOException e) {
            logger.error("Could not convert user from access token: {}, {}", accessToken, e.getMessage(), e);
            return null;
        }
    }
}
