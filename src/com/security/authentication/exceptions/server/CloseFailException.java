package com.security.authentication.exceptions.server;

public class CloseFailException extends RuntimeException {
    public CloseFailException(String message, Exception e) {
        super(message, e);
    }
}
