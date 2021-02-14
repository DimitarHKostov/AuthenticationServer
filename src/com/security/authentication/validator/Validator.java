package com.security.authentication.validator;

import com.security.authentication.command.Command;
import com.security.authentication.exceptions.general.InvalidNumberOfArgumentsException;
import com.security.authentication.exceptions.register.InvalidDataException;
import com.security.authentication.validator.subvalidators.AddAdminValidator;
import com.security.authentication.validator.subvalidators.DeleteUserValidator;
import com.security.authentication.validator.subvalidators.LogInValidator;
import com.security.authentication.validator.subvalidators.LogOutValidator;
import com.security.authentication.validator.subvalidators.RegisterValidator;
import com.security.authentication.validator.subvalidators.RemoveAdminValidator;
import com.security.authentication.validator.subvalidators.ResetPasswordValidator;
import com.security.authentication.validator.subvalidators.UpdateUserValidator;

import java.util.List;

public class Validator {
    public static void validateNotNull(Object parameter, String parameterName) throws IllegalArgumentException {
        if (parameter == null) {
            throw new IllegalArgumentException(parameterName + " is null");
        }
    }

    public static void validateEnoughArguments(List<String> arguments, int necessaryArguments)
            throws InvalidNumberOfArgumentsException {
        validateNotNull(arguments, "arguments");

        if (arguments.size() != necessaryArguments) {
            throw new InvalidNumberOfArgumentsException("invalid number of arguments");
        }
    }

    public static String validateCommand(Command command) {
        validateNotNull(command, "command");

        return switch (command.type()) {
            case REGISTER -> validateRegisterCommand(command);
            case LOGIN -> validateLogInCommand(command);
            case LOGOUT -> validateLogOutCommand(command);
            case DELETE_USER -> validateDeleteUserCommand(command);
            case UPDATE_USER -> validateUpdateUserCommand(command);
            case ADD_ADMIN_USER -> validateAddAdminCommand(command);
            case RESET_PASSWORD -> validateResetPasswordCommand(command);
            case REMOVE_ADMIN_USER -> validateRemoveAdminCommand(command);
            case INVALID -> null;
        };
    }

    private static String validateRegisterCommand(Command command) {
        try {
            RegisterValidator.validate(command.parameters());
        } catch (InvalidDataException e) {
            return "<Missing authentication sentinel/data>";
        } catch (InvalidNumberOfArgumentsException e) {
            return "<Wrong number of arguments>";
        }

        return null;
    }

    private static String validateLogInCommand(Command command) {
        try {
            LogInValidator.validate(command.parameters());
        } catch (InvalidDataException e) {
            return "<Missing authentication sentinel/data>";
        } catch (InvalidNumberOfArgumentsException e) {
            return "<Wrong number of arguments>";
        }

        return null;
    }

    private static String validateLogOutCommand(Command command) {
        try {
            LogOutValidator.validate(command.parameters());
        } catch (InvalidDataException e) {
            return "<Missing authentication sentinel/data>";
        } catch (InvalidNumberOfArgumentsException e) {
            return "<Wrong number of arguments>";
        }

        return null;
    }

    private static String validateAddAdminCommand(Command command) {
        try {
            AddAdminValidator.validate(command.parameters());
        } catch (InvalidDataException e) {
            return "<Missing authentication sentinel/data>";
        } catch (InvalidNumberOfArgumentsException e) {
            return "<Wrong number of arguments>";
        }

        return null;
    }

    private static String validateDeleteUserCommand(Command command) {
        try {
            DeleteUserValidator.validate(command.parameters());
        } catch (InvalidDataException e) {
            return "<Missing authentication sentinel/data>";
        } catch (InvalidNumberOfArgumentsException e) {
            return "<Wrong number of arguments>";
        }

        return null;
    }

    private static String validateRemoveAdminCommand(Command command) {
        try {
            RemoveAdminValidator.validate(command.parameters());
        } catch (InvalidDataException e) {
            return "<Missing authentication sentinel/data>";
        } catch (InvalidNumberOfArgumentsException e) {
            return "<Wrong number of arguments>";
        }

        return null;
    }

    private static String validateResetPasswordCommand(Command command) {
        try {
            ResetPasswordValidator.validate(command.parameters());
        } catch (InvalidDataException e) {
            return "<Missing authentication sentinel/data>";
        } catch (InvalidNumberOfArgumentsException e) {
            return "<Wrong number of arguments>";
        }

        return null;
    }

    private static String validateUpdateUserCommand(Command command) {
        try {
            UpdateUserValidator.validate(command.parameters());
        } catch (InvalidDataException e) {
            return "<Missing authentication sentinel/data>";
        } catch (InvalidNumberOfArgumentsException e) {
            return "<Wrong number of arguments>";
        }

        return null;
    }
}
