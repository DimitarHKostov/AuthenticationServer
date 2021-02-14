package com.security.authentication.validator;

import com.security.authentication.command.Command;
import com.security.authentication.enums.CommandType;
import com.security.authentication.exceptions.general.InvalidNumberOfArgumentsException;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class ValidatorTest {
    @Test(expected = IllegalArgumentException.class)
    public void testValidateNotNullExpectedIllegalArgumentException() {
        Validator.validateNotNull(null, "asd");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidateEnoughArgumentsExpectedIllegalArugmentException() {
        Validator.validateEnoughArguments(null, 0);
    }

    @Test(expected = InvalidNumberOfArgumentsException.class)
    public void testValidateEnoughArgumentsExpectedInvalidNumberOfArguments() {
        Validator.validateEnoughArguments(List.of("arg1", "arg2"), 3);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidateCommandExpectedIllegalArgumentException() {
        Validator.validateCommand(null);
    }

    @Test
    public void testValidateCommandRegisterExpectedWrongNumberOfArguments() {
        String actual = Validator.validateCommand(new Command(CommandType.REGISTER, List.of("--username", "username",
                "--password", "password",
                "--first-name", "first-name")));

        String expected = "<Wrong number of arguments>";

        assertEquals("expecting exactly the same", expected, actual);
    }

    @Test
    public void testValidateCommandRegisterExpectedMissingSentinel() {
        String actual = Validator.validateCommand(new Command(CommandType.REGISTER, List.of("--username", "username",
                "--password", "password",
                "--first-name", "first-name",
                "--last-name", "last-name",
                "randomSentinel", "email")));

        String expected = "<Missing authentication sentinel/data>";

        assertEquals("expecting exactly the same", expected, actual);
    }

    @Test
    public void testValidateCommandRegisterExpectedNull() {
        String actual = Validator.validateCommand(new Command(CommandType.REGISTER, List.of("--username", "username",
                "--password", "password",
                "--first-name", "first-name",
                "--last-name", "last-name",
                "--email", "email")));

        assertNull("expecting exactly the same", actual);
    }

    @Test
    public void testValidateCommandLogInExpectedWrongNumberOfArguments() {
        String actual = Validator.validateCommand(new Command(CommandType.LOGIN, List.of("--username", "username",
                "--password", "password",
                "--first-name", "first-name")));

        String expected = "<Wrong number of arguments>";

        assertEquals("expecting exactly the same", expected, actual);
    }

    @Test
    public void testValidateCommandLogInCombinationExpectedMissingSentinel() {
        String actual = Validator.validateCommand(new Command(CommandType.LOGIN, List.of("--username", "username",
                "randomSentinel", "password")));

        String expected = "<Missing authentication sentinel/data>";

        assertEquals("expecting exactly the same", expected, actual);
    }

    @Test
    public void testValidateCommandLogInSessionExpectedMissingSentinel() {
        String actual = Validator.validateCommand(new Command(CommandType.LOGIN, List.of("session", "ses")));

        String expected = "<Missing authentication sentinel/data>";

        assertEquals("expecting exactly the same", expected, actual);
    }

    @Test
    public void testValidateCommandLogInCombinationExpectedNull() {
        String actual = Validator.validateCommand(new Command(CommandType.LOGIN, List.of("--username", "username",
                "--password", "password")));

        assertNull("expecting exactly the same", actual);
    }

    @Test
    public void testValidateCommandLogInSessionExpectedNull() {
        String actual =
                Validator.validateCommand(new Command(CommandType.LOGIN, List.of("--session-id", "username")));

        assertNull("expecting exactly the same", actual);
    }

    @Test
    public void testValidateCommandLogOutExpectedWrongNumberOfArguments() {
        String actual = Validator.validateCommand(new Command(CommandType.LOGOUT, List.of("sessionId")));

        String expected = "<Wrong number of arguments>";

        assertEquals("expecting exactly the same", expected, actual);
    }

    @Test
    public void testValidateCommandLogOutExpectedMissingSentinel() {
        String actual = Validator.validateCommand(new Command(CommandType.LOGOUT, List.of("sessionId", "session")));

        String expected = "<Missing authentication sentinel/data>";

        assertEquals("expecting exactly the same", expected, actual);
    }

    @Test
    public void testValidateCommandLogOutExpectedNull() {
        String actual = Validator.validateCommand(new Command(CommandType.LOGOUT, List.of("--session-id", "session")));

        assertNull("expecting exactly the same", actual);
    }

    @Test
    public void testValidateCommandDeleteUserExpectedWrongNumberOfArguments() {
        String actual = Validator.validateCommand(new Command(CommandType.DELETE_USER, List.of("--session-id", "ses")));

        String expected = "<Wrong number of arguments>";

        assertEquals("expecting exactly the same", expected, actual);
    }

    @Test
    public void testValidateCommandDeleteUserExpectedMissingSentinel() {
        String actual =
                Validator.validateCommand(new Command(CommandType.DELETE_USER, List.of("--session-id", "session",
                        "--password", "asd")));

        String expected = "<Missing authentication sentinel/data>";

        assertEquals("expecting exactly the same", expected, actual);
    }

    @Test
    public void testValidateCommandDeleteUserExpectedNull() {
        String actual =
                Validator.validateCommand(new Command(CommandType.DELETE_USER, List.of("--session-id", "session",
                        "--username", "username")));

        assertNull("expecting exactly the same", actual);
    }

    @Test
    public void testValidateCommandUpdateUserExpectedWrongNumberOfArguments() {
        String actual =
                Validator.validateCommand(new Command(CommandType.UPDATE_USER, List.of("--session-id", "ses", "asd")));

        String expected = "<Wrong number of arguments>";

        assertEquals("expecting exactly the same", expected, actual);
    }

    @Test
    public void testValidateCommandUpdateUserExpectedMissingSentinel() {
        String actual =
                Validator.validateCommand(new Command(CommandType.UPDATE_USER, List.of("-session-id", "session",
                        "--password", "asd")));

        String expected = "<Missing authentication sentinel/data>";

        assertEquals("expecting exactly the same", expected, actual);
    }

    @Test
    public void testValidateCommandUpdateUserExpectedNull() {
        String actual =
                Validator.validateCommand(new Command(CommandType.UPDATE_USER, List.of("--session-id", "session",
                        "--username", "username")));

        assertNull("expecting exactly the same", actual);
    }

    @Test
    public void testValidateCommandAddAdminUserExpectedWrongNumberOfArguments() {
        String actual =
                Validator.validateCommand(new Command(CommandType.ADD_ADMIN_USER, List.of("--session-id", "ses")));

        String expected = "<Wrong number of arguments>";

        assertEquals("expecting exactly the same", expected, actual);
    }

    @Test
    public void testValidateCommandAddAdminUserExpectedMissingSentinel() {
        String actual =
                Validator.validateCommand(new Command(CommandType.ADD_ADMIN_USER, List.of("--session-id", "session",
                        "--password", "asd")));

        String expected = "<Missing authentication sentinel/data>";

        assertEquals("expecting exactly the same", expected, actual);
    }

    @Test
    public void testValidateCommandAddAdminUserExpectedNull() {
        String actual =
                Validator.validateCommand(new Command(CommandType.ADD_ADMIN_USER, List.of("--session-id", "session",
                        "--username", "username")));

        assertNull("expecting exactly the same", actual);
    }

    @Test
    public void testValidateCommandRemoveAdminUserExpectedWrongNumberOfArguments() {
        String actual =
                Validator.validateCommand(new Command(CommandType.REMOVE_ADMIN_USER, List.of("--session-id", "ses")));

        String expected = "<Wrong number of arguments>";

        assertEquals("expecting exactly the same", expected, actual);
    }

    @Test
    public void testValidateCommandRemoveAdminUserExpectedMissingSentinel() {
        String actual =
                Validator.validateCommand(new Command(CommandType.REMOVE_ADMIN_USER, List.of("--session-id", "session",
                        "--password", "asd")));

        String expected = "<Missing authentication sentinel/data>";

        assertEquals("expecting exactly the same", expected, actual);
    }

    @Test
    public void testValidateCommandRemoveAdminUserExpectedNull() {
        String actual =
                Validator.validateCommand(new Command(CommandType.REMOVE_ADMIN_USER, List.of("--session-id", "session",
                        "--username", "username")));

        assertNull("expecting exactly the same", actual);
    }

    @Test
    public void testValidateCommandResetPasswordExpectedWrongNumberOfArguments() {
        String actual =
                Validator.validateCommand(new Command(CommandType.RESET_PASSWORD, List.of("--session-id", "ses")));

        String expected = "<Wrong number of arguments>";

        assertEquals("expecting exactly the same", expected, actual);
    }

    @Test
    public void testValidateCommandResetPasswordExpectedMissingSentinel() {
        String actual =
                Validator.validateCommand(new Command(CommandType.RESET_PASSWORD, List.of("--session-id", "session",
                        "--password", "asd",
                        "asd", "asd",
                        "asd", "asd")));

        String expected = "<Missing authentication sentinel/data>";

        assertEquals("expecting exactly the same", expected, actual);
    }

    @Test
    public void testValidateCommandResetPasswordExpectedNull() {
        String actual =
                Validator.validateCommand(new Command(CommandType.RESET_PASSWORD, List.of("--session-id", "session",
                        "--username", "username",
                        "--old-password", "oldPass",
                        "--new-password", "newPass")));

        assertNull("expecting exactly the same", actual);
    }

    @Test
    public void testValidateCommandInvalidExpectedNull() {
        String actual =
                Validator.validateCommand(new Command(CommandType.INVALID, List.of("--session-id", "session",
                        "--username", "username",
                        "--old-password", "oldPass",
                        "--new-password", "newPass")));

        assertNull("expecting exactly the same", actual);
    }
}
