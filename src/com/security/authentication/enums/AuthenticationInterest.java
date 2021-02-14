package com.security.authentication.enums;

import com.security.authentication.validator.Validator;

public enum AuthenticationInterest {
    USERNAME("--username"),
    PASSWORD("--password"),
    FIRST_NAME("--first-name"),
    LAST_NAME("--last-name"),
    EMAIL("--email"),
    INVALID("");

    private final String interest;

    AuthenticationInterest(String interest) {
        this.interest = interest;
    }

    public String getInterest() {
        return this.interest;
    }

    public static AuthenticationInterest getType(String command) {
        Validator.validateNotNull(command, "command");

        for (AuthenticationInterest interest : AuthenticationInterest.values()) {
            if (command.equals(interest.getInterest())) {
                return interest;
            }
        }

        return INVALID;
    }
}
