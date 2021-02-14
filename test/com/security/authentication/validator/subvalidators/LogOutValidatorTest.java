package com.security.authentication.validator.subvalidators;

import com.security.authentication.exceptions.general.InvalidNumberOfArgumentsException;
import com.security.authentication.exceptions.register.InvalidDataException;
import org.junit.Test;

import java.util.List;

public class LogOutValidatorTest {
    @Test(expected = IllegalArgumentException.class)
    public void testValidateExpectedIllegalArgumentException() {
        LogOutValidator.validate(null);
    }

    @Test(expected = InvalidNumberOfArgumentsException.class)
    public void testValidateExpectedInvalidNumberOfArgumentsException() {
        LogOutValidator.validate(List.of("sessionId"));
    }

    @Test(expected = InvalidDataException.class)
    public void testValidateExpectedInvalidDataException() {
        LogOutValidator.validate(List.of("sessionId", "session"));
    }
}
