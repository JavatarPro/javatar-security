package pro.javatar.security.jwt.bean.representation;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import pro.javatar.security.jwt.RSATokenVerifier;
import pro.javatar.security.jwt.TokenVerifier;
import pro.javatar.security.jwt.bean.jws.JWSBuilder;
import pro.javatar.security.jwt.exception.VerificationException;
import pro.javatar.security.jwt.utils.Time;
import pro.javatar.security.jwt.utils.TokenUtil;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AccessTokenTest {
    private static final String REALM = "realm2";
    private static final String CLIENT_ID = "configuration-service";
    private static final String USER_ROLE = "SEC_ADMIN";

    private static KeyPair idpPair;
    private static KeyPair badPair;

    @BeforeAll
    static void setupCerts() throws Exception {
        idpPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        badPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    }

    @Test
    void testTokenAuthHappyFlow() throws Exception {
        AccessToken accessToken = new AccessToken();
        accessToken.type(TokenUtil.TOKEN_TYPE_BEARER)
                .expiration(Time.currentTime() + 100)
                .subject("CN=Client")
                .issuer("http://localhost:8080/auth/realm2")
                .addAccess(CLIENT_ID).addRole(USER_ROLE);

        String tokenString = new JWSBuilder()
                                     .jsonContent(accessToken)
                                     .rsa256(idpPair.getPrivate());

        assertThat(TokenVerifier.getRealm(tokenString), is(REALM));

        AccessToken parsedAccessToken =
                RSATokenVerifier.getAccessToken(tokenString, idpPair.getPublic(), REALM, true, true);

        assertThat(parsedAccessToken.getSubject(), is("CN=Client"));
        assertThat(parsedAccessToken.getResourceAccess(CLIENT_ID).getRoles().size(), is(1));
        assertTrue(parsedAccessToken.getResourceAccess(CLIENT_ID).getRoles().contains(USER_ROLE));
    }

    @Test
    void testTokenAuthIsExpired() {
        AccessToken accessToken = new AccessToken();
        accessToken.type(TokenUtil.TOKEN_TYPE_BEARER)
                .expiration(Time.currentTime() - 100)
                .subject("CN=Client")
                .issuer("http://localhost:8080/auth/realm2")
                .addAccess(CLIENT_ID).addRole(USER_ROLE);

        String tokenString = new JWSBuilder()
                                     .jsonContent(accessToken)
                                     .rsa256(idpPair.getPrivate());

        assertThat(TokenVerifier.getRealm(tokenString), is(REALM));
        assertThrows(VerificationException.class, () -> RSATokenVerifier.getAccessToken(tokenString, idpPair.getPublic(), REALM, true, true));
    }

    @Test
    void testTokenAuthBadSignature() {
        AccessToken accessToken = new AccessToken();
        accessToken.type(TokenUtil.TOKEN_TYPE_BEARER)
                .expiration(Time.currentTime() - 100)
                .subject("CN=Client")
                .issuer("http://localhost:8080/auth/realm2")
                .addAccess(CLIENT_ID).addRole(USER_ROLE);

        String tokenString = new JWSBuilder()
                                     .jsonContent(accessToken)
                                     .rsa256(idpPair.getPrivate());

        assertThat(TokenVerifier.getRealm(tokenString), is(REALM));
        assertThrows(VerificationException.class, () -> RSATokenVerifier.getAccessToken(tokenString, badPair.getPublic(), REALM, true, true));
    }

    @Test
    void testTokenAuthIncorrectRealm() {
        AccessToken accessToken = new AccessToken();
        accessToken.type(TokenUtil.TOKEN_TYPE_BEARER)
                .expiration(Time.currentTime() - 100)
                .subject("CN=Client")
                .issuer("http://localhost:8080/auth/realm2")
                .addAccess(CLIENT_ID).addRole(USER_ROLE);

        String tokenString = new JWSBuilder()
                                     .jsonContent(accessToken)
                                     .rsa256(idpPair.getPrivate());

        assertThrows(VerificationException.class, () ->
                                                          RSATokenVerifier.getAccessToken(tokenString, idpPair.getPublic(), "incorrect realm", true, true));
    }
}