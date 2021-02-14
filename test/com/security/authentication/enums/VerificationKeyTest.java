package com.security.authentication.enums;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class VerificationKeyTest {
    @Test(expected = IllegalArgumentException.class)
    public void testGetTypeExpectedIllegalArgumentException() {
        VerificationKey.getType(null);
    }

    @Test
    public void testGetTypeExpectedSessionId() {
        VerificationKey actual = VerificationKey.getType("--session-id");
        VerificationKey expected = VerificationKey.SESSION_ID;

        assertEquals("expecting session id verification key", expected, actual);
    }

    @Test
    public void testGetTypeExpectedInvalid() {
        VerificationKey actual = VerificationKey.getType("random");
        VerificationKey expected = VerificationKey.INVALID;

        assertEquals("expecting invalid verification key", expected, actual);
    }
}
