package com.security.authentication.validator.subvalidators;

import com.security.authentication.enums.AuthenticationInterest;
import com.security.authentication.exceptions.general.InvalidNumberOfArgumentsException;
import com.security.authentication.exceptions.register.InvalidDataException;
import com.security.authentication.validator.Validator;

import java.util.List;

public class RegisterValidator {
    private static final int REGISTER_NECESSARY_ARGUMENTS_NUMBER = 10;

    public static void validate(List<String> arguments) throws InvalidDataException, InvalidNumberOfArgumentsException {
        Validator.validateNotNull(arguments, "arguments");
        Validator.validateEnoughArguments(arguments, REGISTER_NECESSARY_ARGUMENTS_NUMBER);

        String usernameToken = arguments.get(0);
        String passwordToken = arguments.get(2);
        String firstNameToken = arguments.get(4);
        String lastNameToken = arguments.get(6);
        String emailToken = arguments.get(8);

        if (!validateUsernameToken(usernameToken)
                || !validatePasswordToken(passwordToken)
                || !validateFirstNameToken(firstNameToken)
                || !validateLastNameToken(lastNameToken)
                || !validateEmailToken(emailToken)) {
            throw new InvalidDataException("missing register token");
        }
    }

    private static boolean validateUsernameToken(String argument) {
        return AuthenticationInterest.getType(argument) == AuthenticationInterest.USERNAME;
    }

    private static boolean validatePasswordToken(String argument) {
        return AuthenticationInterest.getType(argument) == AuthenticationInterest.PASSWORD;
    }

    private static boolean validateFirstNameToken(String argument) {
        return AuthenticationInterest.getType(argument) == AuthenticationInterest.FIRST_NAME;
    }

    private static boolean validateLastNameToken(String argument) {
        return AuthenticationInterest.getType(argument) == AuthenticationInterest.LAST_NAME;
    }

    private static boolean validateEmailToken(String argument) {
        return AuthenticationInterest.getType(argument) == AuthenticationInterest.EMAIL;
    }
}
