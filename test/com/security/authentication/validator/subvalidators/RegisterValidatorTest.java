package com.security.authentication.validator.subvalidators;

import com.security.authentication.exceptions.general.InvalidNumberOfArgumentsException;
import com.security.authentication.exceptions.register.InvalidDataException;
import org.junit.Test;

import java.util.List;

public class RegisterValidatorTest {
    @Test(expected = IllegalArgumentException.class)
    public void testValidateExpectedIllegalArgumentException() {
        RegisterValidator.validate(null);
    }

    @Test(expected = InvalidNumberOfArgumentsException.class)
    public void testValidateExpectedInvalidNumberOfArgumentsException() {
        RegisterValidator.validate(List.of("--username", "username",
                "--password", "password",
                "--first-name", "first-name"));
    }

    @Test(expected = InvalidDataException.class)
    public void testValidateExpectedInvalidDataException() {
        RegisterValidator.validate(List.of("--username", "username",
                "--password", "password",
                "--first-name", "first-name",
                "--last-name", "last-name",
                "randomSentinel", "email"));
    }
}
