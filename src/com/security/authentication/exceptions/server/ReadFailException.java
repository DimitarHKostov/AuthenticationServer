package com.security.authentication.exceptions.server;

public class ReadFailException extends RuntimeException {
    public ReadFailException(String message, Exception e) {
        super(message, e);
    }
}
