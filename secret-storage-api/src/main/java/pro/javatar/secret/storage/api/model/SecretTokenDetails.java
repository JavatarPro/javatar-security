package pro.javatar.secret.storage.api.model;

public class SecretTokenDetails {

    private static final String EMPTY_STRING = "";

    private String accessToken;

    private String refreshToken;

    private String realm;

    private String sessionId;

    private String ipAddress;

    public String getAccessToken() {
        if (isBlank(accessToken)) return EMPTY_STRING;
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public SecretTokenDetails withAccessToken(String accessToken) {
        this.accessToken = accessToken;
        return this;
    }

    public String getRefreshToken() {
        if (isBlank(refreshToken)) return EMPTY_STRING;
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public SecretTokenDetails withRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
        return this;
    }

    public String getRealm() {
        if (isBlank(realm)) return EMPTY_STRING;
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public SecretTokenDetails withRealm(String realm) {
        this.realm = realm;
        return this;
    }

    public boolean isEmpty() {
        if (isBlank(this.accessToken)) return false;
        if (isBlank(this.refreshToken)) return false;
        return true;
    }

    public static boolean isEmpty(SecretTokenDetails secretTokenDetails) {
        if (secretTokenDetails == null) return false;
        if (isBlank(secretTokenDetails.accessToken)) return false;
        if (isBlank(secretTokenDetails.refreshToken)) return false;
        return true;
    }

    private static boolean isBlank(CharSequence cs) {
        int strLen;
        if (cs != null && (strLen = cs.length()) != 0) {
            for(int i = 0; i < strLen; ++i) {
                if (!Character.isWhitespace(cs.charAt(i))) {
                    return false;
                }
            }
            return true;
        } else {
            return true;
        }
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    @Override
    public String toString() {
        return "SecretTokenDetails{" +
                "accessToken='" + accessToken + '\'' +
                ", refreshToken='" + refreshToken + '\'' +
                ", realm='" + realm + '\'' +
                ", sessionId='" + sessionId + '\'' +
                ", ipAddress='" + ipAddress + '\'' +
                '}';
    }
}
