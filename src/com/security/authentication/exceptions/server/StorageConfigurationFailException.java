package com.security.authentication.exceptions.server;

public class StorageConfigurationFailException extends RuntimeException {
    public StorageConfigurationFailException(String message, Exception e) {
        super(message, e);
    }
}
