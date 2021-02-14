package com.security.authentication.token;

import com.security.authentication.enums.ChangeRequest;
import org.junit.Test;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class RequestExtractorTest {
    @Test(expected = IllegalArgumentException.class)
    public void testExtractExpectedIllegalArgumentException() {
        RequestExtractor.extract(null);
    }

    @Test
    public void testExtractExpectedEmptyRequestSet() {
        Map<ChangeRequest, String> actual = RequestExtractor.extract(List.of("--session-id", "ses"));

        assertEquals("expecting empty hash map", 0, actual.size());
    }

    @Test
    public void testExtractExpectedChangePasswordRequest() {
        Map<ChangeRequest, String> actual =
                RequestExtractor.extract(List.of("--session-id", "ses", "--new-password", "newPass"));

        Map<ChangeRequest, String> expected = Map.of(ChangeRequest.NEW_PASSWORD, "newPass");

        assertEquals("both have size of 1", expected.size(), actual.size());

        assertTrue("expecting change password request", actual.containsKey(ChangeRequest.NEW_PASSWORD));
        assertFalse("expecting change password request", actual.containsKey(ChangeRequest.NEW_EMAIL));
    }

    @Test
    public void testExtractExpectedAllRequested() {
        Map<ChangeRequest, String> actual =
                RequestExtractor.extract(
                        List.of("--session-id", "ses",
                                "--new-password", "newPass",
                                "--new-username", "newUsername",
                                "--new-first-name", "newFN",
                                "--new-last-name", "newLN"));

        Map<ChangeRequest, String> expected = Map.of(ChangeRequest.NEW_PASSWORD, "newPass",
                ChangeRequest.NEW_USERNAME, "newUsername",
                ChangeRequest.NEW_FIRST_NAME, "newFN",
                ChangeRequest.NEW_LAST_NAME, "newLN");

        assertEquals("both have size of 4", expected.size(), actual.size());

        assertTrue("expecting change password request", actual.containsKey(ChangeRequest.NEW_PASSWORD));
        assertTrue("expecting change password request", actual.containsKey(ChangeRequest.NEW_USERNAME));
        assertTrue("expecting change password request", actual.containsKey(ChangeRequest.NEW_FIRST_NAME));
        assertTrue("expecting change password request", actual.containsKey(ChangeRequest.NEW_LAST_NAME));
    }
}
