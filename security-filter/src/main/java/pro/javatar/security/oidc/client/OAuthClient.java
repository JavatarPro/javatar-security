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
import org.springframework.stereotype.Component;
import pro.javatar.security.oidc.model.OAuth2Constants;
import pro.javatar.security.oidc.model.TokenDetails;
import pro.javatar.security.oidc.SecurityConstants;
import pro.javatar.security.oidc.exceptions.*;
import pro.javatar.security.oidc.services.OidcAuthenticationHelper;
import pro.javatar.security.oidc.services.OidcConfiguration;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

@Component
public class OAuthClient {
    private static final Logger logger = LoggerFactory.getLogger(OAuthClient.class);

    @Autowired
    private OidcConfiguration oidcConfiguration;

    @Autowired
    private OidcAuthenticationHelper oidcAuthenticationHelper;

    public TokenDetails obtainTokenDetailsByAuthorizationCode(String code, String redirectUrl) {
        List<BasicNameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.AUTHORIZATION_CODE));
        params.add(new BasicNameValuePair(OAuth2Constants.CODE, code));
        params.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ID, oidcConfiguration.getClientId()));
        params.add(new BasicNameValuePair(OAuth2Constants.CLIENT_SECRET, oidcConfiguration.getClientSecret()));
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
        params.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ID, oidcConfiguration.getClientId()));
        params.add(new BasicNameValuePair(OAuth2Constants.CLIENT_SECRET, oidcConfiguration.getClientSecret()));

        try {
            return obtainTokenDetails(params);
        } catch (Exception e) {
            logger.error("could not obtain token by refresh token: {}", e.getMessage(), e);
            throw new ObtainRefreshTokenException();
        }
    }

    public TokenDetails obtainTokenDetailsByApplicationCredentials() {
        String username = oidcConfiguration.getUsername();
        String password = oidcConfiguration.getUserPassword();

        return obtainTokenDetailsByApplicationCredentials(username, password);
    }

    public TokenDetails obtainTokenDetailsByRunOnBehalfOfUserCredentials(String username, String realm) {
        String password = oidcConfiguration.getRunOnBehalfOfUserPassword(username, realm);
        return obtainTokenDetailsByApplicationCredentials(username, password, realm);
    }

    public TokenDetails obtainTokenDetailsByApplicationCredentials(String username, String password) {
        String realm = oidcAuthenticationHelper.getRealmForCurrentRequest();
        return obtainTokenDetailsByApplicationCredentials(username, password, realm);
    }

    public TokenDetails obtainTokenDetailsByApplicationCredentials(String username, String password, String realm) {
        List<BasicNameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.PASSWORD));
        params.add(new BasicNameValuePair(OAuth2Constants.USERNAME, username));
        params.add(new BasicNameValuePair(OAuth2Constants.PASSWORD, password));
        params.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ID, oidcConfiguration.getClientId()));
        params.add(new BasicNameValuePair(OAuth2Constants.CLIENT_SECRET, oidcConfiguration.getClientSecret()));
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
        String realm = oidcAuthenticationHelper.getRealmForCurrentRequest();
        return obtainTokenDetails(realm, params);
    }

    TokenDetails obtainTokenDetails(String realm, List<BasicNameValuePair> params)
            throws URISyntaxException, IOException {
        URIBuilder uri = new URIBuilder(prepareTokenEndpointUrl(realm));

        CloseableHttpClient httpClient = null;
        CloseableHttpResponse httpResponse = null;
        try {
            httpClient = HttpClients.createDefault();
            HttpPost requestBase = new HttpPost(uri.build());
            logger.debug("Create POST method on uri: {}", uri.build());
            requestBase.addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);

            logger.debug("Query parameters: {}", maskedParams(params));
            requestBase.setEntity(new UrlEncodedFormEntity(params));

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
        return oidcConfiguration.getIdentityProviderHost() +
                oidcConfiguration.getTokenEndpoint().replace("{realm}", realm);
    }

    private TokenDetails parseTokenFromJsonString(String responseJsonString) {
        JSONParser jsonParser = new JSONParser();
        Object parsed = null;
        try {
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
        TokenDetails tokenDetails =
                oidcAuthenticationHelper.generateTokenDetails(accessToken, refreshToken);
        tokenDetails.setAccessExpiredIn(String.valueOf(responseJson.get(OAuth2Constants.EXPIRES_IN)));
        tokenDetails.setRefreshExpiredIn(String.valueOf(responseJson.get(OAuth2Constants.REFRESH_EXPIRES_IN)));
        return tokenDetails;
    }

    public void setOidcConfiguration(OidcConfiguration oidcConfiguration) {
        this.oidcConfiguration = oidcConfiguration;
    }

    public void setOidcAuthenticationHelper(OidcAuthenticationHelper oidcAuthenticationHelper) {
        this.oidcAuthenticationHelper = oidcAuthenticationHelper;
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
}
