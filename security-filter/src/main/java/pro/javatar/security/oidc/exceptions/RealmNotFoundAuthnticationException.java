/*
 * Copyright (c) 2018 Javatar LLC
 * All rights reserved.
 */

package pro.javatar.security.oidc.exceptions;

import org.springframework.http.HttpStatus;

public class RealmNotFoundAuthnticationException extends AuthenticationException{

    public RealmNotFoundAuthnticationException() {
        code = "404RealmNotFound";
        status = HttpStatus.NOT_FOUND;
        message = "Realm not found.";
        devMessage = "Realm not found.";
    }

    public RealmNotFoundAuthnticationException(String message) {
        super(message);
    }

    public RealmNotFoundAuthnticationException(String message, String devMessage) {
        super(message, devMessage);
    }
}
