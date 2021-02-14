package com.security.authentication.enums;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class AuthenticationInterestTest {
    @Test(expected = IllegalArgumentException.class)
    public void testGetTypeExpectedIllegalArgumentException() {
        AuthenticationInterest.getType(null);
    }

    @Test
    public void testGetTypeExpectedUsername() {
        AuthenticationInterest actual = AuthenticationInterest.getType("--username");
        AuthenticationInterest expected = AuthenticationInterest.USERNAME;

        assertEquals("expecting username authentication interest", expected, actual);
    }

    @Test
    public void testGetTypeExpectedPassword() {
        AuthenticationInterest actual = AuthenticationInterest.getType("--password");
        AuthenticationInterest expected = AuthenticationInterest.PASSWORD;

        assertEquals("expecting password authentication interest", expected, actual);
    }

    @Test
    public void testGetTypeExpectedFirstName() {
        AuthenticationInterest actual = AuthenticationInterest.getType("--first-name");
        AuthenticationInterest expected = AuthenticationInterest.FIRST_NAME;

        assertEquals("expecting first name authentication interest", expected, actual);
    }

    @Test
    public void testGetTypeExpectedLastName() {
        AuthenticationInterest actual = AuthenticationInterest.getType("--last-name");
        AuthenticationInterest expected = AuthenticationInterest.LAST_NAME;

        assertEquals("expecting last name authentication interest", expected, actual);
    }

    @Test
    public void testGetTypeExpectedEmail() {
        AuthenticationInterest actual = AuthenticationInterest.getType("--email");
        AuthenticationInterest expected = AuthenticationInterest.EMAIL;

        assertEquals("expecting email authentication interest", expected, actual);
    }

    @Test
    public void testGetTypeExpectedInvalid() {
        AuthenticationInterest actual = AuthenticationInterest.getType("random");
        AuthenticationInterest expected = AuthenticationInterest.INVALID;

        assertEquals("expecting invalid authentication interest", expected, actual);
    }
}
