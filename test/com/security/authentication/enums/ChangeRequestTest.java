package com.security.authentication.enums;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ChangeRequestTest {
    @Test(expected = IllegalArgumentException.class)
    public void testGetTypeExpectedIllegalArgumentException() {
        ChangeRequest.getType(null);
    }

    @Test
    public void testGetTypeExpectedNewUsername() {
        ChangeRequest actual = ChangeRequest.getType("--new-username");
        ChangeRequest expected = ChangeRequest.NEW_USERNAME;

        assertEquals("expecting new username change request", expected, actual);
    }

    @Test
    public void testGetTypeExpectedNewFirstName() {
        ChangeRequest actual = ChangeRequest.getType("--new-first-name");
        ChangeRequest expected = ChangeRequest.NEW_FIRST_NAME;

        assertEquals("expecting new first name change request", expected, actual);
    }

    @Test
    public void testGetTypeExpectedNewLastName() {
        ChangeRequest actual = ChangeRequest.getType("--new-last-name");
        ChangeRequest expected = ChangeRequest.NEW_LAST_NAME;

        assertEquals("expecting new last name change request", expected, actual);
    }

    @Test
    public void testGetTypeExpectedNewEmail() {
        ChangeRequest actual = ChangeRequest.getType("--new-email");
        ChangeRequest expected = ChangeRequest.NEW_EMAIL;

        assertEquals("expecting new email change request", expected, actual);
    }

    @Test
    public void testGetTypeExpectedOldPassword() {
        ChangeRequest actual = ChangeRequest.getType("--old-password");
        ChangeRequest expected = ChangeRequest.OLD_PASSWORD;

        assertEquals("expecting old password sentinel", expected, actual);
    }

    @Test
    public void testGetTypeExpectedNewPassword() {
        ChangeRequest actual = ChangeRequest.getType("--new-password");
        ChangeRequest expected = ChangeRequest.NEW_PASSWORD;

        assertEquals("expecting new password change request", expected, actual);
    }

    @Test
    public void testGetTypeExpectedInvalid() {
        ChangeRequest actual = ChangeRequest.getType("random");
        ChangeRequest expected = ChangeRequest.INVALID;

        assertEquals("expecting invalid change request", expected, actual);
    }
}
