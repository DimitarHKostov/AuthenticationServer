package com.security.authentication.defend.tracker;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.nio.channels.SocketChannel;

import static org.junit.Assert.assertEquals;

@RunWith(MockitoJUnitRunner.class)
public class BruteForceTrackerTest {
    Tracker tracker = new BruteForceTracker();

    @Mock
    private SocketChannel channel;

    @Test(expected = IllegalArgumentException.class)
    public void testIncrementExpectedIllegalArgumentException() {
        tracker.increment(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRemoveExpectedIllegalArgumentException() {
        tracker.increment(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetTrackCountExpectedIllegalArgumentException() {
        tracker.remove(null);
    }

    @Test
    public void testGetTrackCountExpectedZero() {
        int actual = tracker.getTrackCount(channel);

        assertEquals("expected 0 tracks", 0, actual);
    }

    @Test
    public void testIncrementExpectedOneMore() {
        int actual;
        actual = tracker.getTrackCount(channel);

        assertEquals("expected 0 tracks at the beginning", 0, actual);

        tracker.increment(channel);
        actual = tracker.getTrackCount(channel);

        assertEquals("expected 1 track", 1, actual);
    }

    @Test
    public void testRemoveExpectedNoMoreTracks() {
        int actual;

        tracker.increment(channel);
        actual = tracker.getTrackCount(channel);

        assertEquals("expected 1 track", 1, actual);

        tracker.remove(channel);
        actual = tracker.getTrackCount(channel);

        assertEquals("expected 0 tracks", 0, actual);
    }

    @Test
    public void testGetTrackCountExpectedThree() {
        for (int i = 0; i < 3; i++) {
            tracker.increment(channel);
        }

        int actual = tracker.getTrackCount(channel);

        assertEquals("expected 3 tracks", 3, actual);
    }
}
