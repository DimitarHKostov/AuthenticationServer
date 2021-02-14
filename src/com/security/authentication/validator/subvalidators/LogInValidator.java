package com.security.authentication.validator.subvalidators;

import com.security.authentication.enums.AuthenticationInterest;
import com.security.authentication.enums.VerificationKey;
import com.security.authentication.exceptions.general.InvalidNumberOfArgumentsException;
import com.security.authentication.exceptions.register.InvalidDataException;
import com.security.authentication.validator.Validator;

import java.util.List;

public class LogInValidator {
    private static final int LOGIN_NECESSARY_ARGUMENTS_NUMBER = 4;
    private static final int LOGIN_SESSION_ARGUMENTS_NUMBER = 2;

    public static void validate(List<String> arguments) throws InvalidDataException, InvalidNumberOfArgumentsException {
        Validator.validateNotNull(arguments, "arguments");

        if (arguments.size() != LOGIN_NECESSARY_ARGUMENTS_NUMBER
                && arguments.size() != LOGIN_SESSION_ARGUMENTS_NUMBER) {
            throw new InvalidNumberOfArgumentsException("Wrong number of arguments");
        }

        if (arguments.size() == LOGIN_NECESSARY_ARGUMENTS_NUMBER) {
            String usernameToken = arguments.get(0);
            String passwordToken = arguments.get(2);

            if (!validateUsernameToken(usernameToken)
                    || !validatePasswordToken(passwordToken)) {
                throw new InvalidDataException("missing token");
            }
        } else {
            String sessionId = arguments.get(0);
            if (!validateSessionToken(sessionId)) {
                throw new InvalidDataException("missing token");
            }
        }
    }

    private static boolean validateUsernameToken(String argument) {
        return AuthenticationInterest.getType(argument) == AuthenticationInterest.USERNAME;
    }

    private static boolean validatePasswordToken(String argument) {
        return AuthenticationInterest.getType(argument) == AuthenticationInterest.PASSWORD;
    }

    private static boolean validateSessionToken(String argument) {
        return VerificationKey.getType(argument) == VerificationKey.SESSION_ID;
    }
}
