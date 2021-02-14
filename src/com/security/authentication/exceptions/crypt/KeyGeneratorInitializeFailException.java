package com.security.authentication.exceptions.crypt;

public class KeyGeneratorInitializeFailException extends RuntimeException {
    public KeyGeneratorInitializeFailException(String message, Exception e) {
        super(message, e);
    }
}
