package com.security.authentication.validator.subvalidators;

import com.security.authentication.exceptions.general.InvalidNumberOfArgumentsException;
import com.security.authentication.exceptions.register.InvalidDataException;
import org.junit.Test;

import java.util.List;

public class AddAdminValidatorTest {
    @Test(expected = IllegalArgumentException.class)
    public void testValidateExpectedIllegalArgumentException() {
        AddAdminValidator.validate(null);
    }

    @Test(expected = InvalidNumberOfArgumentsException.class)
    public void testValidateExpectedInvalidNumberOfArgumentsException() {
        AddAdminValidator.validate(List.of("--session-id", "ses"));
    }

    @Test(expected = InvalidDataException.class)
    public void testValidateExpectedInvalidDataException() {
        AddAdminValidator.validate(List.of("--session-id", "session", "--password", "asd"));
    }
}
