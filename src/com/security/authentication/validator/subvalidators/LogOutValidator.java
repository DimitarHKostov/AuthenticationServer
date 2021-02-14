package com.security.authentication.validator.subvalidators;

import com.security.authentication.enums.VerificationKey;
import com.security.authentication.exceptions.general.InvalidNumberOfArgumentsException;
import com.security.authentication.exceptions.register.InvalidDataException;
import com.security.authentication.validator.Validator;

import java.util.List;

public class LogOutValidator {
    private static final int LOGOUT_NECESSARY_ARGUMENTS_NUMBER = 2;

    public static void validate(List<String> arguments) throws InvalidDataException, InvalidNumberOfArgumentsException {
        Validator.validateNotNull(arguments, "arguments");
        Validator.validateEnoughArguments(arguments, LOGOUT_NECESSARY_ARGUMENTS_NUMBER);

        String sessionToken = arguments.get(0);

        if (!validateSessionToken(sessionToken)) {
            throw new InvalidDataException("missing token");
        }
    }

    private static boolean validateSessionToken(String argument) {
        return VerificationKey.getType(argument) == VerificationKey.SESSION_ID;
    }
}
