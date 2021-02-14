package com.security.authentication.exceptions.login;

public class ExpiredSessionIdException extends Exception {
    public ExpiredSessionIdException(String message) {
        super(message);
    }
}
