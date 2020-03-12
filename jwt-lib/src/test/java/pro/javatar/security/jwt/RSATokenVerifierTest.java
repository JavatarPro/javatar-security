package pro.javatar.security.jwt;

import org.junit.jupiter.api.Test;
import pro.javatar.security.jwt.bean.representation.AccessToken;
import pro.javatar.security.jwt.exception.JwtException;
import pro.javatar.security.jwt.exception.TokenExpirationException;
import pro.javatar.security.jwt.exception.VerificationException;
import pro.javatar.security.jwt.utils.JwtTokenGenerator;
import pro.javatar.security.jwt.utils.Time;

import java.security.PublicKey;
import java.util.Arrays;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RSATokenVerifierTest {

    @Test
    void getAccessToken() throws Exception {
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
    void getAccessTokenWithSettings() throws Exception {
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

    @Test
    void getAccessTokenWithSettingsRealmVerificationException() throws Exception {
        JwtTokenGenerator tokenGenerator =
                new JwtTokenGenerator("http://localhost:8080/auth/test-realm",
                        "configuration-service", Arrays.asList("USER_READ", "USER_WRITE"));
        String accessToken = tokenGenerator.generateJwtAccessToken();

        assertThrows(VerificationException.class, () -> RSATokenVerifier
                .create(accessToken)
                .checkRealm(true).realmUrl("test-realm1")
                .publicKey(tokenGenerator.getIdpPair().getPublic())
                .verify()
                .getToken());
    }

    @Test
    void getAccessTokenWithSettingsPublicKeyVerificationException() throws Exception {
        JwtTokenGenerator tokenGenerator =
                new JwtTokenGenerator("http://localhost:8080/auth/test-realm",
                        "configuration-service", Arrays.asList("USER_READ", "USER_WRITE"));
        String accessToken = tokenGenerator.generateJwtAccessToken();

        assertThrows(JwtException.class, () -> RSATokenVerifier
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
                .getToken());
    }

    @Test
    void getAccessTokenWithSettingExpirationException() throws Exception {
        JwtTokenGenerator tokenGenerator =
                new JwtTokenGenerator(Time.currentTime() - 100, "http://localhost:8080/auth/test-realm",
                        "configuration-service", Arrays.asList("USER_READ", "USER_WRITE"));
        String accessToken = tokenGenerator.generateJwtAccessToken();

        assertThrows(TokenExpirationException.class, () -> RSATokenVerifier
                .create(accessToken)
                .checkRealm(true).realmUrl("test-realm")
                .publicKey(tokenGenerator.getIdpPair().getPublic())
                .verify()
                .getToken());
    }
}