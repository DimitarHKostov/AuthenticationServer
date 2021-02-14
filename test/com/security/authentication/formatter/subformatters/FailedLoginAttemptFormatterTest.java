package com.security.authentication.formatter.subformatters;

import org.junit.Test;

import java.time.LocalDateTime;

import static org.junit.Assert.assertEquals;

public class FailedLoginAttemptFormatterTest {
    private static final String IP = "196.124.0.1";

    @Test(expected = IllegalArgumentException.class)
    public void testFormatExpectedIllegalArgumentException() {
        FailedLogInAttemptFormatter.format(null);
    }

    @Test
    public void testFormatExpectedExactSameLog() {
        String actual = FailedLogInAttemptFormatter.format(IP);

        actual = actual.substring(actual.indexOf("Type"));

        String expected =  "Type: Failed log in attempt"
                + System.lineSeparator()
                + "IP: " + IP
                + System.lineSeparator()
                + "........................"
                + System.lineSeparator();

        assertEquals("expecting exact same log", expected, actual);
    }
}
