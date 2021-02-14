package com.security.authentication.enums;

import com.security.authentication.validator.Validator;

public enum CommandType {
    REGISTER("register"),
    LOGIN("login"),
    UPDATE_USER("update-user"),
    RESET_PASSWORD("reset-password"),
    LOGOUT("logout"),
    ADD_ADMIN_USER("add-admin-user"),
    REMOVE_ADMIN_USER("remove-admin-user"),
    DELETE_USER("delete-user"),
    INVALID("invalid");

    private final String command;

    CommandType(String command) {
        this.command = command;
    }

    public String getMessage() {
        return this.command;
    }

    public static CommandType getType(String command) {
        Validator.validateNotNull(command, "command");

        for (CommandType commandType : CommandType.values()) {
            if (command.startsWith(commandType.getMessage())) {
                return commandType;
            }
        }

        return CommandType.INVALID;
    }
}
