package com.security.authentication.handler;

import com.security.authentication.generator.SessionGenerator;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class SessionHandlerTest {
    @Mock
    private SessionGenerator generator;

    @InjectMocks
    private SessionHandler sessionHandler;

    @Test(expected = IllegalArgumentException.class)
    public void testIsValidExpectedIllegalArgumentException() {
        sessionHandler.isValid(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidateExpectedIllegalArgumentException() {
        sessionHandler.invalidate(null);
    }

    @Test
    public void testGenerateExpectingSessionId() {
        when(generator.generate()).thenReturn("sessionId");

        String actual = sessionHandler.generate();
        String expected = "sessionId";

        assertEquals("expecting generated session id", expected, actual);
    }

    @Test
    public void testIsValidExpectingValidSessionId() {
        when(generator.generate()).thenReturn("sessionId");

        sessionHandler.generate();

        assertTrue("expecting valid session id", sessionHandler.isValid("sessionId"));
    }

    @Test
    public void testIsValidExpectingInValidSessionId() {
        when(generator.generate()).thenReturn("sessionId");

        sessionHandler.generate();

        assertFalse("expecting invalid session id", sessionHandler.isValid("sessionId-1"));
    }

    @Test
    public void testInvalidateExpectingWrongSessionId() {
        when(generator.generate()).thenReturn("sessionId");

        sessionHandler.generate();

        assertTrue("expecting valid session id", sessionHandler.isValid("sessionId"));

        sessionHandler.invalidate("sessionId");

        assertFalse("expecting invalid session id", sessionHandler.isValid("sessionId"));
    }
}
