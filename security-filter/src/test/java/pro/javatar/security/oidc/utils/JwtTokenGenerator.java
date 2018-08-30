package pro.javatar.security.oidc.utils;

import pro.javatar.security.jwt.bean.jws.JWSBuilder;
import pro.javatar.security.jwt.bean.representation.AccessToken;
import pro.javatar.security.jwt.utils.Time;
import pro.javatar.security.jwt.utils.TokenUtil;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.List;

public class JwtTokenGenerator {
    private KeyPair idpPair;
    private KeyPair badPair;
    private AccessToken accessToken;

    /**
     * Generator with valid token lifespan and without roles
     *
     * @param issuer   url who generated token (i.e. http://localhost:8080/auth/realm2)
     * @param clientId client id
     * @throws NoSuchAlgorithmException
     */
    public JwtTokenGenerator(String issuer, String clientId) throws NoSuchAlgorithmException {
        this(Time.currentTime() + 100, issuer, clientId, Collections.emptyList());
    }

    /**
     * Generator with valid token lifespan with roles
     *
     * @param issuer   url who generated token (i.e. http://localhost:8080/auth/realm2)
     * @param clientId client id
     * @throws NoSuchAlgorithmException
     */
    public JwtTokenGenerator(String issuer, String clientId, List<String> roles) throws NoSuchAlgorithmException {
        this(Time.currentTime() + 100, issuer, clientId, roles);
    }

    public JwtTokenGenerator(int expiration, String issuer, String clientId) throws NoSuchAlgorithmException {
        this(expiration, issuer, clientId, Collections.emptyList());
    }

    public JwtTokenGenerator(int expiration, String issuer, String clientId, List<String> roles) throws NoSuchAlgorithmException {
        idpPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        badPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        accessToken = new AccessToken();
        AccessToken.Access realmClient = accessToken.type(TokenUtil.TOKEN_TYPE_BEARER)
                .expiration(expiration)
                .subject("subject")
                .issuer(issuer)
                .addAccess(clientId);
        if (roles != null && !roles.isEmpty()) {
            for (String role : roles) {
                realmClient.addRole(role);
            }

        }
    }

    public String generateJwtAccessToken() {
        return new JWSBuilder()
                .jsonContent(accessToken)
                .rsa256(idpPair.getPrivate());
    }

    public KeyPair getIdpPair() {
        return idpPair;
    }

    public KeyPair getBadPair() {
        return badPair;
    }

    public AccessToken getAccessToken() {
        return accessToken;
    }
}
