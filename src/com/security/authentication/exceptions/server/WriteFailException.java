package com.security.authentication.exceptions.server;

public class WriteFailException extends RuntimeException {
    public WriteFailException(String message, Exception e) {
        super(message, e);
    }
}
