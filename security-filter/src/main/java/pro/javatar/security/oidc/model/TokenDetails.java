package pro.javatar.security.oidc.model;

import java.time.LocalDateTime;

public class TokenDetails {

    private String accessToken;
    private LocalDateTime accessTokenExpiration;
    private String refreshToken;
    private Class credentialsProvider;
    private String realm;
    private String accessExpiredIn;
    private String refreshExpiredIn;

    public TokenDetails() {
    }

    public TokenDetails(String accessToken, String refreshToken, LocalDateTime accessTokenExpiration) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.accessTokenExpiration = accessTokenExpiration;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public LocalDateTime getAccessTokenExpiration() {
        return accessTokenExpiration;
    }

    public void setAccessTokenExpiration(LocalDateTime accessTokenExpiration) {
        this.accessTokenExpiration = accessTokenExpiration;
    }

    public Class getCredentialsProvider() {
        return credentialsProvider;
    }

    public void setCredentialsProvider(Class credentialsProvider) {
        this.credentialsProvider = credentialsProvider;
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public boolean isEmpty() {
        return accessToken == null || accessToken.trim().isEmpty();
    }

    public boolean isNotEmpty() {
        return !isEmpty();
    }

    public String getMaskedAccessToken() {
        return getMaskedString(accessToken, 7);
    }

    public String getMaskedRefreshToken() {
        return getMaskedString(refreshToken, 7);
    }

    public String getAccessExpiredIn() {
        return accessExpiredIn;
    }

    public void setAccessExpiredIn(String accessExpiredIn) {
        this.accessExpiredIn = accessExpiredIn;
    }

    public String getRefreshExpiredIn() {
        return refreshExpiredIn;
    }

    public void setRefreshExpiredIn(String refreshExpiredIn) {
        this.refreshExpiredIn = refreshExpiredIn;
    }

    private static String getMaskedString(String secret, int lastSymbolsCount) {
        if (secret == null || secret.length() < lastSymbolsCount) {return secret;}
        return "*****" + secret.substring(secret.length() - lastSymbolsCount);
    }

    @Override
    public String toString() {
        return "TokenDetails{" +
                "accessToken='" + getMaskedAccessToken() + '\'' +
                ", accessTokenExpiration=" + accessTokenExpiration +
                ", refreshToken='" + getMaskedRefreshToken() + '\'' +
                ", credentialsProvider=" + credentialsProvider +
                ", accessExpiredIn=" + accessExpiredIn +
                ", refreshExpiredIn=" + refreshExpiredIn +
                ", realm='" + realm + '\'' +
                '}';
    }
}
