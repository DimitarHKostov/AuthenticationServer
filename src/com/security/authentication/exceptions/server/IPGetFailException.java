package com.security.authentication.exceptions.server;

public class IPGetFailException extends RuntimeException {
    public IPGetFailException(String message, Exception e) {
        super(message, e);
    }
}
