package com.security.authentication.validator.subvalidators;

import com.security.authentication.enums.AuthenticationInterest;
import com.security.authentication.enums.ChangeRequest;
import com.security.authentication.enums.VerificationKey;
import com.security.authentication.exceptions.general.InvalidNumberOfArgumentsException;
import com.security.authentication.exceptions.register.InvalidDataException;
import com.security.authentication.validator.Validator;

import java.util.List;

public class ResetPasswordValidator {
    private static final int NECESSARY_ARGUMENTS_NUMBER = 8;

    public static void validate(List<String> arguments) throws InvalidDataException,
            InvalidNumberOfArgumentsException {
        Validator.validateNotNull(arguments, "arguments");
        Validator.validateEnoughArguments(arguments, NECESSARY_ARGUMENTS_NUMBER);

        String sessionToken = arguments.get(0);
        String usernameToken = arguments.get(2);
        String oldPasswordToken = arguments.get(4);
        String newPasswordToken = arguments.get(6);

        if (!validateUsernameToken(usernameToken)
                || !validateSessionToken(sessionToken)
                || !validateOldPasswordToken(oldPasswordToken)
                || !validateNewPasswordToken(newPasswordToken)) {
            throw new InvalidDataException("missing register token");
        }
    }

    private static boolean validateUsernameToken(String argument) {
        return AuthenticationInterest.getType(argument) == AuthenticationInterest.USERNAME;
    }

    private static boolean validateSessionToken(String argument) {
        return VerificationKey.getType(argument) == VerificationKey.SESSION_ID;
    }

    private static boolean validateOldPasswordToken(String argument) {
        return ChangeRequest.getType(argument) == ChangeRequest.OLD_PASSWORD;
    }

    private static boolean validateNewPasswordToken(String argument) {
        return ChangeRequest.getType(argument) == ChangeRequest.NEW_PASSWORD;
    }
}
