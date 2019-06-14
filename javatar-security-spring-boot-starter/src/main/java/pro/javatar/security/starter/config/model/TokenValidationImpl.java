package pro.javatar.security.starter.config.model;

import pro.javatar.security.api.config.SecurityConfig;

/**
 * @author Borys Zora
 * @version 2019-06-14
 */
public class TokenValidationImpl implements SecurityConfig.TokenValidation {

    Boolean checkTokenIsActive = true;
    Boolean skipRefererCheck = true;
    Boolean checkTokenType = true;
    Boolean realmRequired = true;

    @Override
    public Boolean checkTokenIsActive() {
        return checkTokenIsActive;
    }

    @Override
    public Boolean skipRefererCheck() {
        return skipRefererCheck;
    }

    @Override
    public Boolean checkTokenType() {
        return checkTokenType;
    }

    @Override
    public Boolean realmRequired() {
        return realmRequired;
    }

    public void setCheckTokenIsActive(Boolean checkTokenIsActive) {
        this.checkTokenIsActive = checkTokenIsActive;
    }

    public void setSkipRefererCheck(Boolean skipRefererCheck) {
        this.skipRefererCheck = skipRefererCheck;
    }

    public void setCheckTokenType(Boolean checkTokenType) {
        this.checkTokenType = checkTokenType;
    }

    public void setRealmRequired(Boolean realmRequired) {
        this.realmRequired = realmRequired;
    }

    @Override
    public String toString() {
        return "TokenValidationImpl{" +
                "checkTokenIsActive=" + checkTokenIsActive +
                ", skipRefererCheck=" + skipRefererCheck +
                ", checkTokenType=" + checkTokenType +
                ", realmRequired=" + realmRequired +
                '}';
    }
}