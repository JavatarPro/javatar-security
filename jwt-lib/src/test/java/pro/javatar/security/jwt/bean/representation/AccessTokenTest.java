package pro.javatar.security.jwt.bean.representation;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import pro.javatar.security.jwt.RSATokenVerifier;
import pro.javatar.security.jwt.TokenVerifier;
import pro.javatar.security.jwt.bean.jws.JWSBuilder;
import pro.javatar.security.jwt.exception.TokenExpirationException;
import pro.javatar.security.jwt.exception.VerificationException;
import pro.javatar.security.jwt.utils.Time;
import pro.javatar.security.jwt.utils.TokenUtil;

import org.junit.BeforeClass;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class AccessTokenTest {
    private static final String REALM = "realm2";
    private static final String CLIENT_ID = "configuration-service";
    private static final String USER_ROLE = "SEC_ADMIN";

    private static KeyPair idpPair;
    private static KeyPair badPair;

    @BeforeClass
    public static void setupCerts() throws Exception {
        idpPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        badPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    }

    @Test
    public void testTokenAuthHappyFlow() throws Exception {
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

    @SuppressWarnings("Duplicates")
    @Test(expected = TokenExpirationException.class)
    public void testTokenAuthIsExpired() throws Exception {
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
        RSATokenVerifier.getAccessToken(tokenString, idpPair.getPublic(), REALM, true, true);
    }

    @SuppressWarnings("Duplicates")
    @Test(expected = VerificationException.class)
    public void testTokenAuthBadSignature() throws Exception {
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
        RSATokenVerifier.getAccessToken(tokenString, badPair.getPublic(), REALM, true, true);
    }

    @Test(expected = VerificationException.class)
    public void testTokenAuthIncorrectRealm() throws Exception {
        AccessToken accessToken = new AccessToken();
        accessToken.type(TokenUtil.TOKEN_TYPE_BEARER)
                .expiration(Time.currentTime() - 100)
                .subject("CN=Client")
                .issuer("http://localhost:8080/auth/realm2")
                .addAccess(CLIENT_ID).addRole(USER_ROLE);

        String tokenString = new JWSBuilder()
                .jsonContent(accessToken)
                .rsa256(idpPair.getPrivate());

        RSATokenVerifier.getAccessToken(tokenString, idpPair.getPublic(), "incorrect realm", true, true);
    }
}