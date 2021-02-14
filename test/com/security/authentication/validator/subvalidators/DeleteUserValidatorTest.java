package com.security.authentication.validator.subvalidators;

import com.security.authentication.exceptions.general.InvalidNumberOfArgumentsException;
import com.security.authentication.exceptions.register.InvalidDataException;
import org.junit.Test;

import java.util.List;

public class DeleteUserValidatorTest {
    @Test(expected = IllegalArgumentException.class)
    public void testValidateExpectedIllegalArgumentException() {
        DeleteUserValidator.validate(null);
    }

    @Test(expected = InvalidNumberOfArgumentsException.class)
    public void testValidateExpectedInvalidNumberOfArgumentsException() {
        DeleteUserValidator.validate(List.of("--session-id", "ses"));
    }

    @Test(expected = InvalidDataException.class)
    public void testValidateExpectedInvalidDataException() {
        DeleteUserValidator.validate(List.of("--session-id", "session", "--password", "asd"));
    }
}
