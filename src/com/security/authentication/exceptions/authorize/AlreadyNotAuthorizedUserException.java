package com.security.authentication.exceptions.authorize;

public class AlreadyNotAuthorizedUserException extends Exception {
    public AlreadyNotAuthorizedUserException(String message) {
        super(message);
    }
}
