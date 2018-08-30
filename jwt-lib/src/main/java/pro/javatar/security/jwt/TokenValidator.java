package pro.javatar.security.jwt;

import pro.javatar.security.jwt.bean.jws.AlgorithmType;
import pro.javatar.security.jwt.bean.jws.JWSInput;
import pro.javatar.security.jwt.bean.jws.crypto.HMACProvider;
import pro.javatar.security.jwt.bean.jws.crypto.RSAProvider;
import pro.javatar.security.jwt.bean.representation.AccessToken;
import pro.javatar.security.jwt.exception.TokenExpirationException;
import pro.javatar.security.jwt.exception.VerificationException;
import pro.javatar.security.jwt.utils.TokenUtil;

import javax.crypto.SecretKey;
import java.security.PublicKey;

public class TokenValidator {
    private boolean checkTokenType = true;
    private boolean checkActive = true;
    private boolean checkRealm = true;
    private String realm;
    private AlgorithmType algorithmType;
    private PublicKey publicKey;
    private SecretKey secretKey;
    private JWSInput jws;
    private AccessToken token;

    public TokenValidator() {
        this(true, true, true);
    }

    public TokenValidator(boolean checkTokenType, boolean checkActive, boolean checkRealm) {
        this.checkTokenType = checkTokenType;
        this.checkActive = checkActive;
        this.checkRealm = checkRealm;
    }

    public void validate() throws VerificationException, TokenExpirationException {
        validateRealm();
        validateAlgorithmType();
        validateTokenSubject();
        validateTokenType();
        validateIsTokenActive();
    }

    private void validateIsTokenActive() throws TokenExpirationException {
        if (checkActive && !token.isActive()) {
            throw new TokenExpirationException("Token is not active");
        }
    }

    private void validateTokenType() throws VerificationException {
        if (checkTokenType && !TokenUtil.TOKEN_TYPE_BEARER.equalsIgnoreCase(token.getType())) {
            throw new VerificationException(
                    "Token type is incorrect. Expected '" + TokenUtil.TOKEN_TYPE_BEARER
                            + "' but was '" + token.getType() + "'");
        }
    }

    private void validateTokenSubject() throws VerificationException {
        String user = token.getSubject();
        if (user == null) {
            throw new VerificationException("Subject missing in token");
        }

        if (checkRealm && !isRealmValid(token.getIssuer(), realm)) {
            throw new VerificationException(
                    "Invalid token issuer. Expected realm '" + realm + "', but was '"
                            + token.getIssuer() + "'");
        }
    }

    private void validateRealm() throws VerificationException {
        if (checkRealm && realm == null) {
            throw new VerificationException("Realm URL not set");
        }
    }

    private void validateAlgorithmType() throws VerificationException {
        if (AlgorithmType.RSA.equals(algorithmType)) {
            if (publicKey == null) {
                throw new VerificationException("Public key not set");
            }

            if (!RSAProvider.verify(jws, publicKey)) {
                throw new VerificationException("Invalid token signature");
            }
        } else if (AlgorithmType.HMAC.equals(algorithmType)) {
            if (secretKey == null) {
                throw new VerificationException("Secret key not set");
            }

            if (!HMACProvider.verify(jws, secretKey)) {
                throw new VerificationException("Invalid token signature");
            }
        } else {
            throw new VerificationException("Unknown or unsupported token algorithm");
        }
    }

    public TokenValidator setRealm(String realm) {
        this.realm = realm;
        return this;
    }

    public TokenValidator setAlgorithmType(AlgorithmType algorithmType) {
        this.algorithmType = algorithmType;
        return this;
    }

    public TokenValidator setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    public TokenValidator setSecretKey(SecretKey secretKey) {
        this.secretKey = secretKey;
        return this;
    }

    public TokenValidator setJwt(JWSInput jws) {
        this.jws = jws;
        return this;
    }

    public TokenValidator setToken(AccessToken token) {
        this.token = token;
        return this;
    }

    boolean isRealmValid(String issuer, String realm) {
        return !((issuer == null || issuer.isEmpty()) ||
                (realm == null || realm.isEmpty())) &&
                issuer.endsWith("/".concat(realm));
    }
}
