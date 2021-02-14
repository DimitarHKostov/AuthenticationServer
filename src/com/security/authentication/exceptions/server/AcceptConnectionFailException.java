package com.security.authentication.exceptions.server;

public class AcceptConnectionFailException extends RuntimeException {
    public AcceptConnectionFailException(String message, Exception e) {
        super(message, e);
    }
}
