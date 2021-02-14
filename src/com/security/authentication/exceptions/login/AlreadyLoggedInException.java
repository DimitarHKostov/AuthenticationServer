package com.security.authentication.exceptions.login;

public class AlreadyLoggedInException extends Exception {
    public AlreadyLoggedInException(String message) {
        super(message);
    }
}
