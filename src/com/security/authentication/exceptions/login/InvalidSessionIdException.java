package com.security.authentication.exceptions.login;

public class InvalidSessionIdException extends Exception {
    public InvalidSessionIdException(String message) {
        super(message);
    }
}
