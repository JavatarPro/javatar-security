package pro.javatar.security.jwt;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import pro.javatar.security.jwt.bean.representation.AccessToken;
import pro.javatar.security.jwt.exception.JwtException;
import pro.javatar.security.jwt.exception.TokenExpirationException;
import pro.javatar.security.jwt.exception.VerificationException;
import pro.javatar.security.jwt.utils.JwtTokenGenerator;
import pro.javatar.security.jwt.utils.Time;

import org.junit.Test;

import java.security.PublicKey;
import java.util.Arrays;

public class RSATokenVerifierTest {

    @Test
    public void getAccessToken() throws Exception {
        JwtTokenGenerator tokenGenerator =
                new JwtTokenGenerator("http://localhost:8080/auth/test-realm",
                        "configuration-service", Arrays.asList("USER_READ", "USER_WRITE"));
        String accessToken = tokenGenerator.generateJwtAccessToken();

        AccessToken token = RSATokenVerifier.getAccessToken(accessToken,
                tokenGenerator.getIdpPair().getPublic(),
                "test-realm");

        assertThat(token.getIssuer(), is("http://localhost:8080/auth/test-realm"));

        assertThat(token.getResourceAccess().size(), is(1));
        assertThat(token.getResourceAccess().get("configuration-service").getRoles().contains("USER_READ"), is(true));
        assertThat(token.getResourceAccess().get("configuration-service").getRoles().contains("USER_WRITE"), is(true));
    }

    @Test
    public void getAccessTokenWithSettings() throws Exception {
        JwtTokenGenerator tokenGenerator =
                new JwtTokenGenerator("http://localhost:8080/auth/test-realm",
                        "configuration-service", Arrays.asList("USER_READ", "USER_WRITE"));
        String accessToken = tokenGenerator.generateJwtAccessToken();

        AccessToken token = RSATokenVerifier
                .create(accessToken)
                .checkRealm(true).realmUrl("test-realm")
                .publicKey(tokenGenerator.getIdpPair().getPublic())
                .verify()
                .getToken();

        assertThat(token.getIssuer(), is("http://localhost:8080/auth/test-realm"));

        assertThat(token.getResourceAccess().size(), is(1));
        assertThat(token.getResourceAccess().get("configuration-service").getRoles().contains("USER_READ"), is(true));
        assertThat(token.getResourceAccess().get("configuration-service").getRoles().contains("USER_WRITE"), is(true));
    }

    @Test(expected = VerificationException.class)
    public void getAccessTokenWithSettingsRealmVerificationException() throws Exception {
        JwtTokenGenerator tokenGenerator =
                new JwtTokenGenerator("http://localhost:8080/auth/test-realm",
                        "configuration-service", Arrays.asList("USER_READ", "USER_WRITE"));
        String accessToken = tokenGenerator.generateJwtAccessToken();

        RSATokenVerifier
                .create(accessToken)
                .checkRealm(true).realmUrl("test-realm1")
                .publicKey(tokenGenerator.getIdpPair().getPublic())
                .verify()
                .getToken();
    }

    @Test(expected = JwtException.class)
    public void getAccessTokenWithSettingsPublicKeyVerificationException() throws Exception {
        JwtTokenGenerator tokenGenerator =
                new JwtTokenGenerator("http://localhost:8080/auth/test-realm",
                        "configuration-service", Arrays.asList("USER_READ", "USER_WRITE"));
        String accessToken = tokenGenerator.generateJwtAccessToken();

        RSATokenVerifier
                .create(accessToken)
                .checkRealm(true).realmUrl("test-realm")
                .publicKey(new PublicKey() { //incorrect public key
                    @Override
                    public String getAlgorithm() {
                        return null;
                    }

                    @Override
                    public String getFormat() {
                        return null;
                    }

                    @Override
                    public byte[] getEncoded() {
                        return new byte[0];
                    }
                }) //incorrect public key
                .verify()
                .getToken();
    }

    @Test(expected = TokenExpirationException.class)
    public void getAccessTokenWithSettingExpirationException() throws Exception {
        JwtTokenGenerator tokenGenerator =
                new JwtTokenGenerator(Time.currentTime() - 100, "http://localhost:8080/auth/test-realm",
                        "configuration-service", Arrays.asList("USER_READ", "USER_WRITE"));
        String accessToken = tokenGenerator.generateJwtAccessToken();

        RSATokenVerifier
                .create(accessToken)
                .checkRealm(true).realmUrl("test-realm")
                .publicKey(tokenGenerator.getIdpPair().getPublic())
                .verify()
                .getToken();
    }
}