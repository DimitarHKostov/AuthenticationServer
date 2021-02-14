package com.security.authentication.validator.subvalidators;

import com.security.authentication.exceptions.general.InvalidNumberOfArgumentsException;
import com.security.authentication.exceptions.register.InvalidDataException;
import org.junit.Test;

import java.util.List;

public class ResetPasswordValidatorTest {
    @Test(expected = IllegalArgumentException.class)
    public void testValidateExpectedIllegalArgumentException() {
        ResetPasswordValidator.validate(null);
    }

    @Test(expected = InvalidNumberOfArgumentsException.class)
    public void testValidateExpectedInvalidNumberOfArgumentsException() {
        ResetPasswordValidator.validate(List.of("--session-id", "ses"));
    }

    @Test(expected = InvalidDataException.class)
    public void testValidateExpectedInvalidDataException() {
        ResetPasswordValidator.validate(List.of("--session-id", "session",
                "--password", "asd",
                "asd", "asd",
                "asd", "asd"));
    }
}
