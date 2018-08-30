/*
 * Copyright (c) 2018 Javatar LLC
 * All rights reserved.
 */
package pro.javatar.security.oidc.exceptions;

import org.springframework.http.HttpStatus;

public class InvalidUserCredentialsAuthenticationException extends AuthenticationException {

    public InvalidUserCredentialsAuthenticationException() {
        code = "401InvalidUserCredentials";
        status = HttpStatus.UNAUTHORIZED;
        message = "Invalid user credentials.";
        devMessage = "Invalid user credentials.";
    }

    public InvalidUserCredentialsAuthenticationException(String message) {
        super(message);
    }

    public InvalidUserCredentialsAuthenticationException(String message, String devMessage) {
        super(message, devMessage);
    }
}
