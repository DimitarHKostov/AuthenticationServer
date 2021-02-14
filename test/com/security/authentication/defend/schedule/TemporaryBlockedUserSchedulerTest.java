package com.security.authentication.defend.schedule;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.nio.channels.SocketChannel;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(MockitoJUnitRunner.class)
public class TemporaryBlockedUserSchedulerTest {
    Scheduler scheduler = new TemporaryBlockedUserScheduler();

    @Mock
    private SocketChannel channel;

    @Test(expected = IllegalArgumentException.class)
    public void testSuspendExpectedIllegalArgumentException() {
        scheduler.suspend(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testReleaseExpectedIllegalArgumentException() {
        scheduler.release(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testIsSuspendedExpectedIllegalArgumentException() {
        scheduler.isSuspended(null);
    }

    @Test
    public void testSuspendBlocksChannel() {
        assertFalse("expecting ip to not be blocked", scheduler.isSuspended(channel));

        scheduler.suspend(channel);

        assertTrue("expecting ip to be blocked", scheduler.isSuspended(channel));
    }

    @Test
    public void testReleaseUnblocksChannel() {
        scheduler.suspend(channel);

        assertTrue("expecting ip to be blocked", scheduler.isSuspended(channel));

        scheduler.release(channel);

        assertFalse("expecting ip to not be blocked", scheduler.isSuspended(channel));
    }

    @Test
    public void testIsSuspendedIsTrue() {
        scheduler.suspend(channel);

        assertTrue(scheduler.isSuspended(channel));
    }

    @Test
    public void testIsSuspendedIsFalse() {
        assertFalse(scheduler.isSuspended(channel));
    }
}
