package com.security.authentication.defend;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.nio.channels.SocketChannel;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(MockitoJUnitRunner.class)
public class DefenderTest {
    private final Defender defender = new Defender();
    private static final String ip = "196.124.0.5";

    @Mock
    private SocketChannel socketChannel;

    @Test(expected = IllegalArgumentException.class)
    public void testRegisterInvalidTryExpectedIllegalArgumentException() {
        defender.registerInvalidTry(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testClearHistoryExpectedIllegalArgumentException() {
        defender.clearHistory(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testIsBlockedExpectedIllegalArgumentException() {
        defender.registerInvalidTry(null);
    }

    @Test
    public void testIsBlockedExpectedBlockedChannelAfterThreeFailedLogInAttempts() {
        defender.registerInvalidTry(socketChannel);
        defender.registerInvalidTry(socketChannel);
        defender.registerInvalidTry(socketChannel);

        assertTrue("expecting channel to be blocked", defender.isBlocked(socketChannel));
    }

    @Test
    public void testIsBlockedExpectedNotBlockedChannelAfterLessThanThreeFailedLogInAttempts() {
        defender.registerInvalidTry(socketChannel);
        defender.registerInvalidTry(socketChannel);

        assertFalse("expecting channel to not be blocked", defender.isBlocked(socketChannel));
    }
}
