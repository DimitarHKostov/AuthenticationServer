package com.security.authentication.defend;

import com.security.authentication.defend.schedule.Scheduler;
import com.security.authentication.defend.schedule.TemporaryBlockedUserScheduler;
import com.security.authentication.defend.tracker.BruteForceTracker;
import com.security.authentication.defend.tracker.Tracker;
import com.security.authentication.validator.Validator;

import java.nio.channels.SocketChannel;

public class Defender {
    private final Scheduler scheduler = new TemporaryBlockedUserScheduler();
    private final Tracker tracker = new BruteForceTracker();
    private static final int MAX_INVALID_ATTEMPTS = 3;

    public void registerInvalidTry(SocketChannel channel) {
        Validator.validateNotNull(channel, "channel");

        tracker.increment(channel);

        if (tracker.getTrackCount(channel) >= MAX_INVALID_ATTEMPTS) {
            scheduler.suspend(channel);
            tracker.remove(channel);
        }
    }

    public void clearHistory(SocketChannel channel) {
        Validator.validateNotNull(channel, "channel");

        tracker.remove(channel);
    }

    public boolean isBlocked(SocketChannel channel) {
        Validator.validateNotNull(channel, "channel");

        return scheduler.isSuspended(channel);
    }
}
