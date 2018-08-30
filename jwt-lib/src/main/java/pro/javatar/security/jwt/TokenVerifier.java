package pro.javatar.security.jwt;

import pro.javatar.security.jwt.bean.jws.JWSHeader;
import pro.javatar.security.jwt.bean.jws.JWSInput;
import pro.javatar.security.jwt.bean.jws.JWSInputException;
import pro.javatar.security.jwt.bean.representation.AccessToken;
import pro.javatar.security.jwt.exception.TokenExpirationException;
import pro.javatar.security.jwt.exception.VerificationException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.security.PublicKey;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author Andrii Murashkin
 * @version 2018-04-16
 */
public class TokenVerifier {
    private static final Logger logger = LoggerFactory.getLogger(TokenVerifier.class.getName());

    private final String tokenString;
    private PublicKey publicKey;
    private SecretKey secretKey;
    private String realm;
    private boolean checkTokenType = true;
    private boolean checkActive = true;
    private boolean checkRealm = true;

    private JWSInput jws;
    private AccessToken token;

    private static Pattern realmPattern = Pattern.compile("\\b[^-]([\\w-]+)$");

    protected TokenVerifier(String tokenString) {
        this.tokenString = tokenString;
    }

    public static TokenVerifier create(String tokenString) {
        return new TokenVerifier(tokenString);
    }

    public TokenVerifier publicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    public TokenVerifier secretKey(SecretKey secretKey) {
        this.secretKey = secretKey;
        return this;
    }

    public TokenVerifier realm(String realm) {
        this.realm = realm;
        return this;
    }

    public TokenVerifier checkTokenType(boolean checkTokenType) {
        this.checkTokenType = checkTokenType;
        return this;
    }

    public TokenVerifier checkActive(boolean checkActive) {
        this.checkActive = checkActive;
        return this;
    }

    public TokenVerifier checkRealm(boolean checkRealmUrl) {
        this.checkRealm = checkRealmUrl;
        return this;
    }

    public TokenVerifier parse() throws VerificationException {
        if (jws == null) {
            if (tokenString == null) {
                throw new VerificationException("Token not set");
            }

            try {
                jws = new JWSInput(tokenString);
            } catch (JWSInputException e) {
                throw new VerificationException("Failed to parse JWT", e);
            }


            try {
                token = jws.readJsonContent(AccessToken.class);
            } catch (JWSInputException e) {
                throw new VerificationException("Failed to read access token from JWT", e);
            }
        }
        return this;
    }

    public AccessToken getToken() throws VerificationException {
        parse();
        return token;
    }

    public JWSHeader getHeader() throws VerificationException {
        parse();
        return jws.getHeader();
    }

    public static String getRealm(String tokenString) {
        JWSInput jwtInput;
        AccessToken token = null;
        try {
            jwtInput = new JWSInput(tokenString);
            token = jwtInput.readJsonContent(AccessToken.class);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return null;
        }

        String issuer = token.getIssuer();
        Matcher matcher = realmPattern.matcher(issuer);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    public TokenVerifier verify() throws VerificationException, TokenExpirationException {
        parse();

        new TokenValidator(checkTokenType, checkActive, checkRealm)
                .setRealm(realm)
                .setAlgorithmType(getHeader().getAlgorithm().getType())
                .setPublicKey(publicKey)
                .setSecretKey(secretKey)
                .setJwt(jws)
                .setToken(token)
                .validate();

        return this;
    }

}
