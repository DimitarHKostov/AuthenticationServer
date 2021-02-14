package com.security.authentication.exceptions.server;

public class OpenFailException extends RuntimeException {
    public OpenFailException(String message, Exception e) {
        super(message, e);
    }
}
