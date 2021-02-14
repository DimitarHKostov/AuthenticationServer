package com.security.authentication.exceptions.server;

public class ServerConfigurationFailException extends RuntimeException {
    public ServerConfigurationFailException(String message, Exception e) {
        super(message, e);
    }
}
