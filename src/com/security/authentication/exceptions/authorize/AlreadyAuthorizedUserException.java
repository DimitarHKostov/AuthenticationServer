package com.security.authentication.exceptions.authorize;

public class AlreadyAuthorizedUserException extends Exception {
    public AlreadyAuthorizedUserException(String message) {
        super(message);
    }
}
