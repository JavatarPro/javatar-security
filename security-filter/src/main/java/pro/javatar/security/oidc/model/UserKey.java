package pro.javatar.security.oidc.model;

import pro.javatar.security.oidc.utils.StringUtils;
import pro.javatar.security.oidc.utils.StringUtils;

public final class UserKey {

    private String login;

    private String realm;

    public UserKey(String login, String realm) {
        this.login = login;
        this.realm = realm;
        validate();
    }

    void validate() {
        if (StringUtils.isBlank(login) || StringUtils.isBlank(realm)) {
            throw new IllegalStateException("login: " + login + " and realm: " + realm +
                    " must be provided, some of them is blank");
        }
    }

    public String getLogin() {
        return login;
    }

    public String getRealm() {
        return realm;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        UserKey user = (UserKey) o;

        if (!login.equals(user.login)) return false;
        return realm.equals(user.realm);
    }

    @Override
    public int hashCode() {
        int result = login.hashCode();
        result = 31 * result + realm.hashCode();
        return result;
    }

    @Override
    public String toString() {
        return "UserKey{" +
                "login='" + login + '\'' +
                ", realm='" + realm + '\'' +
                '}';
    }
}
