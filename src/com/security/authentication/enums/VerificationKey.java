package com.security.authentication.enums;

import com.security.authentication.validator.Validator;

public enum VerificationKey {
    SESSION_ID("--session-id"),
    INVALID("");

    private final String key;

    VerificationKey(String key) {
        this.key = key;
    }

    public String getKey() {
        return key;
    }

    public static VerificationKey getType(String command) {
        Validator.validateNotNull(command, "command");

        for (VerificationKey verificationKey : VerificationKey.values()) {
            if (command.equals(verificationKey.getKey())) {
                return verificationKey;
            }
        }

        return INVALID;
    }
}
