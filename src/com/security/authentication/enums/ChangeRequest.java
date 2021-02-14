package com.security.authentication.enums;

import com.security.authentication.validator.Validator;

public enum ChangeRequest {
    NEW_USERNAME("--new-username"),
    NEW_FIRST_NAME("--new-first-name"),
    NEW_LAST_NAME("--new-last-name"),
    NEW_EMAIL("--new-email"),
    OLD_PASSWORD("--old-password"),
    NEW_PASSWORD("--new-password"),
    INVALID("");

    private final String changeRequest;

    ChangeRequest(String changeRequest) {
        this.changeRequest = changeRequest;
    }

    public String getRequest() {
        return changeRequest;
    }

    public static ChangeRequest getType(String command) {
        Validator.validateNotNull(command, "command");

        for (ChangeRequest request : ChangeRequest.values()) {
            if (command.equals(request.getRequest())) {
                return request;
            }
        }

        return ChangeRequest.INVALID;
    }
}
