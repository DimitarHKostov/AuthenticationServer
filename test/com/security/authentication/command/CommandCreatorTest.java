package com.security.authentication.command;

import com.security.authentication.enums.CommandType;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;

public class CommandCreatorTest {
    @Test(expected = IllegalArgumentException.class)
    public void testNewCommandExpectedIllegalArgumentException() {
        CommandCreator.newCommand(null);
    }

    @Test
    public void testNewCommandInvalidCommand() {
        Command actual = CommandCreator.newCommand("register");
        Command expected = new Command(CommandType.INVALID, null);

        assertEquals("should be invalid", expected, actual);
    }

    @Test
    public void testNewCommandExpectManyArguments() {
        Command actual = CommandCreator.newCommand("register --username user --password pass");
        Command expected = new Command(CommandType.REGISTER, List.of("--username", "user", "--password", "pass"));

        assertEquals("should be exactly the same", expected, actual);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testExtractArgumentsExpectedIllegalArgumentException() {
        CommandCreator.extractArguments(null);
    }

    @Test
    public void testExtractArgumentsManyArguments() {
        List<String> actual = CommandCreator.extractArguments("login --session-id asdfgh");
        List<String> expected = List.of("--session-id", "asdfgh");

        assertEquals("should be exactly the same", expected, actual);
    }
}
