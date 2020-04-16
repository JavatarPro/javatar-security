package pro.javatar.security.oidc.client;

import org.apache.http.HttpStatus;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import pro.javatar.security.api.config.SecurityConfig;
import pro.javatar.security.jwt.TokenVerifier;
import pro.javatar.security.jwt.adapter.AdapterRSATokenVerifier;
import pro.javatar.security.jwt.bean.representation.AccessToken;
import pro.javatar.security.jwt.exception.TokenExpirationException;
import pro.javatar.security.jwt.exception.VerificationException;
import pro.javatar.security.oidc.SecurityConstants;
import pro.javatar.security.oidc.exceptions.*;
import pro.javatar.security.oidc.model.OAuth2Constants;
import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.services.OidcConfiguration;
import pro.javatar.security.oidc.services.PublicKeyCacheService;
import pro.javatar.security.oidc.services.api.RealmService;
import pro.javatar.security.oidc.utils.StringUtils;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;

@Service
public class OAuthClient {

    private static final Logger logger = LoggerFactory.getLogger(OAuthClient.class);

    // TODO remove this field
    @Deprecated
    private OidcConfiguration oidcConfiguration;

    private RealmService realmService;

    private PublicKeyCacheService publicKeyCacheService;

    private SecurityConfig config;

    @Autowired
    public OAuthClient(OidcConfiguration oidcConfiguration,
                       RealmService realmService,
                       PublicKeyCacheService publicKeyCacheService,
                       SecurityConfig config) {
        this.oidcConfiguration = oidcConfiguration;
        this.realmService = realmService;
        this.publicKeyCacheService = publicKeyCacheService;
        this.config = config;
    }

    public TokenDetails obtainTokenDetailsByAuthorizationCode(String code, String redirectUrl) {
        List<BasicNameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.AUTHORIZATION_CODE));
        params.add(new BasicNameValuePair(OAuth2Constants.CODE, code));
        params.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ID, config.identityProvider().client()));
        params.add(new BasicNameValuePair(OAuth2Constants.CLIENT_SECRET, config.identityProvider().secret()));
        params.add(new BasicNameValuePair(OAuth2Constants.REDIRECT_URI, redirectUrl));
        logger.debug("Redirect URI is {}", redirectUrl);

        try {
            return obtainTokenDetails(params);
        } catch (Exception e) {
            logger.error("could not obtain token by authorizationCode: {}", e.getMessage(), e);
            throw new ExchangeTokenByCodeAuthenticationException();
        }
    }

    public TokenDetails obtainTokenDetailsByRefreshToken(String refreshToken) {
        List<BasicNameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.REFRESH_TOKEN));
        params.add(new BasicNameValuePair(OAuth2Constants.REFRESH_TOKEN, refreshToken));
        params.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ID, config.identityProvider().client()));
        params.add(new BasicNameValuePair(OAuth2Constants.CLIENT_SECRET, config.identityProvider().secret()));

        try {
            return obtainTokenDetails(params);
        } catch (Exception e) {
            logger.error("could not obtain token by refresh token: {}", e.getMessage(), e);
            throw new ObtainRefreshTokenException();
        }
    }

    public TokenDetails obtainTokenDetailsByApplicationCredentials() {
        String username = config.application().user();
        String password = config.application().password();

        return obtainTokenDetailsByApplicationCredentials(username, password);
    }

    public TokenDetails obtainTokenDetailsByRunOnBehalfOfUserCredentials(String username, String realm) {
        String password = oidcConfiguration.getRunOnBehalfOfUserPassword(username, realm);
        return obtainTokenDetailsByApplicationCredentials(username, password, realm);
    }

    public TokenDetails obtainTokenDetailsByApplicationCredentials(String username, String password) {
        String realm = realmService.getRealmForCurrentRequest();
        return obtainTokenDetailsByApplicationCredentials(username, password, realm);
    }

    public TokenDetails obtainTokenDetailsByApplicationCredentials(String username, String password, String realm) {
        List<BasicNameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.PASSWORD));
        params.add(new BasicNameValuePair(OAuth2Constants.USERNAME, username));
        params.add(new BasicNameValuePair(OAuth2Constants.PASSWORD, password));
        params.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ID, config.identityProvider().client()));
        params.add(new BasicNameValuePair(OAuth2Constants.CLIENT_SECRET, config.identityProvider().secret()));
        logger.debug("Trying to obtain token details for realm {} with authentication {}", realm, maskedParams(params));

        try {
            return obtainTokenDetails(realm, params);
        } catch (InvalidUserCredentialsAuthenticationException e) {
            logger.error("Invalid serCredentialsAuthenticationException: {}", e.getMessage(), e);
            throw new InvalidUserCredentialsAuthenticationException();
        } catch (RealmNotFoundAuthnticationException e) {
            logger.error("Realm {} not found: {}", realm, e.getMessage(), e);
            throw new RealmNotFoundAuthnticationException();
        } catch (Exception e) {
            logger.error("could not obtain token by application default user's credentials: {}", e.getMessage(), e);
            throw new ObtainTokenByUserCredentialAuthenticationException();
        }
    }

    private TokenDetails obtainTokenDetails(List<BasicNameValuePair> params)
            throws URISyntaxException, IOException {
        String realm = realmService.getRealmForCurrentRequest();
        return obtainTokenDetails(realm, params);
    }

    TokenDetails obtainTokenDetails(String realm, List<BasicNameValuePair> params)
            throws URISyntaxException, IOException {
        URIBuilder uri = new URIBuilder(prepareTokenEndpointUrl(realm));

        CloseableHttpClient httpClient = null;
        CloseableHttpResponse httpResponse = null;
        try {
            httpClient = createDefaultHttpClient();
            HttpPost requestBase = new HttpPost(uri.build());
            logger.debug("Create POST method on uri: {}", uri.build());
            requestBase.addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);

            logger.debug("Query parameters: {}", maskedParams(params));
            requestBase.setEntity(new UrlEncodedFormEntity(params, StandardCharsets.UTF_8));

            httpResponse = httpClient.execute(requestBase);

            int statusCode = httpResponse.getStatusLine().getStatusCode();
            logger.debug("Response status is {}", statusCode);
            String responseJson = EntityUtils.toString(httpResponse.getEntity());
            if (statusCode != HttpStatus.SC_OK) {
                logger.debug("Response body {}", responseJson);
                if (statusCode == HttpStatus.SC_NOT_FOUND) {
                    throw new RealmNotFoundAuthnticationException();
                }
                throwAuthenticationException(responseJson);
            }
            return parseTokenFromJsonString(responseJson);
        } finally {
            if (httpResponse != null) {
                httpResponse.close();
            }
            if (httpClient != null) {
                httpClient.close();
            }
        }
    }

    private void throwAuthenticationException(String responseJsonString) {
        String errorDescription = responseJsonString;
        try {
            JSONParser jsonParser = new JSONParser();
            Object parsed = jsonParser.parse(responseJsonString);
            JSONObject responseJson = (JSONObject) parsed;
            String error = (String) responseJson.get(SecurityConstants.ERROR);
            errorDescription = (String) responseJson.get(SecurityConstants.ERROR_DESCRIPTION);
            if (SecurityConstants.INVALID_GRANT.equals(error)) {
                throw new InvalidUserCredentialsAuthenticationException(errorDescription);
            }
        } catch (ParseException e) {
            logger.debug("Could not prepare message for exception for responseJsonString: {}", responseJsonString);
        }
        throw new ExchangeTokenByCodeAuthenticationException(errorDescription);
    }

    String prepareTokenEndpointUrl(String realm) {
        return config.identityProvider().url() +
                       oidcConfiguration.getTokenEndpoint().replace("{realm}", realm);
    }

    private TokenDetails parseTokenFromJsonString(String responseJsonString) {
        JSONParser jsonParser = new JSONParser();
        Object parsed;
        try {
            // TODO parse and validation token should be separate things, we just receive token
            parsed = jsonParser.parse(responseJsonString);
        } catch (ParseException e) {
            String message = "Could not parse json token to convert it to token details";
            logger.error("{}, responseJsonString: {}", message, responseJsonString, e);
            ParseTokenAuthenticationException pe = new ParseTokenAuthenticationException();
            pe.setMessage(message);
            pe.setDevMessage(e.getMessage());
            throw pe;
        }
        JSONObject responseJson = (JSONObject) parsed;
        String accessToken = (String) responseJson.get(OAuth2Constants.ACCESS_TOKEN);
        String refreshToken = (String) responseJson.get(OAuth2Constants.REFRESH_TOKEN);
        TokenDetails tokenDetails = generateTokenDetails(accessToken, refreshToken);
        tokenDetails.setAccessExpiredIn(String.valueOf(responseJson.get(OAuth2Constants.EXPIRES_IN)));
        tokenDetails.setRefreshExpiredIn(String.valueOf(responseJson.get(OAuth2Constants.REFRESH_EXPIRES_IN)));
        return tokenDetails;
    }

    public TokenDetails generateTokenDetails(String accessToken, String refreshToken) {
        if (StringUtils.isBlank(accessToken))
            return new TokenDetails();
        AccessToken token;
        try {
            token = parseAccessToken(accessToken, realmService.getRealmFromToken(accessToken));
        } catch (VerificationException e) {
            logger.error("Malicious token: {}, realm: {}", accessToken, TokenVerifier.getRealm(accessToken), e);
            throw new MaliciousBearerJwtTokenAuthenticationException();
        } catch (TokenExpirationException e) {
            logger.debug("Access token is expired trying to refresh one...", e);
            TokenDetails tokenDetails;
            String realmFromToken = realmService.getRealmFromToken(accessToken);
            try {
                tokenDetails = obtainTokenDetailsByRefreshToken(refreshToken);
                token = parseAccessToken(tokenDetails.getAccessToken(), realmFromToken);
                return createTokenDetails(tokenDetails.getAccessToken(), tokenDetails.getRefreshToken(),
                                          token.getExpiration());
            } catch (Exception e1) {
                logger.error("Refresh token is spoiled: {}, realm: {}", StringUtils.getMaskedString(refreshToken),
                             realmFromToken, e1);
                throw new RefreshTokenObsoleteAuthenticationException();
            }
        }
        return createTokenDetails(accessToken, refreshToken, token.getExpiration());
    }

    private TokenDetails createTokenDetails(String accessToken, String refreshToken, int expiration) {
        LocalDateTime accessTokenExpiration =
                LocalDateTime.ofInstant(Instant.ofEpochSecond(expiration), ZoneId.systemDefault());
        return new TokenDetails(accessToken, refreshToken, accessTokenExpiration);
    }

    private List<BasicNameValuePair> maskedParams(List<BasicNameValuePair> params) {
        ArrayList<BasicNameValuePair> maskedParam = new ArrayList<>();
        for (BasicNameValuePair basicNameValuePair : params) {
            if (OAuth2Constants.PASSWORD.equals(basicNameValuePair.getName()) ||
                        OAuth2Constants.CLIENT_SECRET.equals(basicNameValuePair.getName())) {
                maskedParam.add(new BasicNameValuePair(basicNameValuePair.getName(), "********"));
            }
        }
        return maskedParam;
    }

    public AccessToken parseAccessToken(String accessToken, String realm) throws VerificationException,
                                                                                         TokenExpirationException {
        logger.debug("Token realm is {}", realm);
        String publicKeyByRealm = publicKeyCacheService.getPublicKeyByRealm(realm);
        logger.debug("Public key [{}] was retrieved by realm={}", publicKeyByRealm, realm);
        try {
            return getAccessToken(accessToken, realm, publicKeyByRealm);
        } catch (Exception e) { // TODO catch different exceptions
            logger.trace("The first attempt to get access token is invalid. Trying again with refreshed public key.", e);
            String publicKey = publicKeyCacheService.refreshPublicKey(realm);
            return getAccessToken(accessToken, realm, publicKey);
        }
    }

    CloseableHttpClient createDefaultHttpClient() {
        return HttpClients.createDefault();
    }

    private AccessToken getAccessToken(String accessToken, String realm, String publicKeyByRealm)
            throws TokenExpirationException, VerificationException {
        return AdapterRSATokenVerifier.verifyToken(
                publicKeyByRealm,
                accessToken,
                realm,
                config.tokenValidation().checkTokenIsActive(),
                config.tokenValidation().checkTokenType());
    }

    public void setConfig(SecurityConfig config) {
        this.config = config;
    }

    public void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }
}
