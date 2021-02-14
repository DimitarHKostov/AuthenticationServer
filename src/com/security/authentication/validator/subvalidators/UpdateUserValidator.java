package com.security.authentication.validator.subvalidators;

import com.security.authentication.enums.VerificationKey;
import com.security.authentication.exceptions.general.InvalidNumberOfArgumentsException;
import com.security.authentication.exceptions.register.InvalidDataException;
import com.security.authentication.validator.Validator;

import java.util.List;

public class UpdateUserValidator {


    public static void validate(List<String> arguments) throws InvalidDataException,
            InvalidNumberOfArgumentsException {
        Validator.validateNotNull(arguments, "arguments");

        int numberOfArguments = arguments.size();
        boolean validNumberOfArguments = numberOfArguments >= 2 && numberOfArguments <= 8 && numberOfArguments % 2 == 0;

        if (!validNumberOfArguments) {
            throw new InvalidNumberOfArgumentsException("Wrong number of arguments");
        }

        String sessionToken = arguments.get(0);

        if (!validateSessionToken(sessionToken)) {
            throw new InvalidDataException("missing register token");
        }
    }

    private static boolean validateSessionToken(String argument) {
        return VerificationKey.getType(argument) == VerificationKey.SESSION_ID;
    }
}
