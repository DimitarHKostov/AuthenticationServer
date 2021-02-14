package com.security.authentication.exceptions.crypt;

public class CypherInitializeFailException extends RuntimeException {
    public CypherInitializeFailException(String message, Exception e) {
        super(message, e);
    }
}
