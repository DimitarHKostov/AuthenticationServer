package com.security.authentication.exceptions.authorize;

public class NotAuthorizedUserException extends Exception {
    public NotAuthorizedUserException(String message) {
        super(message);
    }
}
