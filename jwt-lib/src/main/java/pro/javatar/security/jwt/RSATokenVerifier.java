package pro.javatar.security.jwt;

import pro.javatar.security.jwt.bean.jws.JWSHeader;
import pro.javatar.security.jwt.bean.representation.AccessToken;
import pro.javatar.security.jwt.exception.TokenExpirationException;
import pro.javatar.security.jwt.exception.VerificationException;

import java.security.PublicKey;

public class RSATokenVerifier {

    private TokenVerifier tokenVerifier;

    private RSATokenVerifier(String tokenString) {
        this.tokenVerifier = TokenVerifier.create(tokenString);
    }

    public static RSATokenVerifier create(String tokenString) {
        return new RSATokenVerifier(tokenString);
    }

    public static AccessToken getAccessToken(String tokenString, PublicKey publicKey, String realmUrl) throws VerificationException, TokenExpirationException {
        return RSATokenVerifier.create(tokenString).publicKey(publicKey).realmUrl(realmUrl).verify().getToken();
    }

    public static AccessToken getAccessToken(String tokenString, PublicKey publicKey, String realmUrl, boolean checkActive, boolean checkTokenType) throws VerificationException, TokenExpirationException {
        return RSATokenVerifier.create(tokenString).publicKey(publicKey).realmUrl(realmUrl).checkActive(checkActive).checkTokenType(checkTokenType).verify().getToken();
    }

    public RSATokenVerifier publicKey(PublicKey publicKey) {
        tokenVerifier.publicKey(publicKey);
        return this;
    }

    public RSATokenVerifier realmUrl(String realmUrl) {
        tokenVerifier.realm(realmUrl);
        return this;
    }

    public RSATokenVerifier checkTokenType(boolean checkTokenType) {
        tokenVerifier.checkTokenType(checkTokenType);
        return this;
    }

    public RSATokenVerifier checkActive(boolean checkActive) {
        tokenVerifier.checkActive(checkActive);
        return this;
    }

    public RSATokenVerifier checkRealm(boolean checkRealmUrl) {
        tokenVerifier.checkRealm(checkRealmUrl);
        return this;
    }

    public RSATokenVerifier parse() throws VerificationException {
        tokenVerifier.parse();
        return this;
    }

    public AccessToken getToken() throws VerificationException {
        return tokenVerifier.getToken();
    }

    public JWSHeader getHeader() throws VerificationException {
        return tokenVerifier.getHeader();
    }

    public RSATokenVerifier verify() throws VerificationException, TokenExpirationException {
        tokenVerifier.verify();
        return this;
    }
}
