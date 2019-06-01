/*
 * Copyright (c) 2019 Javatar LLC
 * All rights reserved.
 */
package pro.javatar.security.gateway.model;

/**
 * @author Andrii Murashkin / Javatar LLC
 * @version 06-03-2019
 */
public class AuthRequestTO {

    protected String email;

    protected String password;

    protected String realm;

    public String getEmail() {
        return email;
    }

    public AuthRequestTO withEmail(String email) {
        this.email = email;
        return this;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public AuthRequestTO withPassword(String password) {
        this.password = password;
        return this;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getRealm() {
        return realm;
    }

    public AuthRequestTO withRealm(String realm) {
        this.realm = realm;
        return this;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    @Override
    public String toString() {
        return "AuthRequestTO{" +
                "email='" + email + '\'' +
                ", password='******'" +
                ", realm='" + realm + '\'' +
                '}';
    }
}
