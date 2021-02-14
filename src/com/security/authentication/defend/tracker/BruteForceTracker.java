package com.security.authentication.defend.tracker;

import com.security.authentication.validator.Validator;

import java.nio.channels.SocketChannel;
import java.util.HashMap;
import java.util.Map;

public class BruteForceTracker implements Tracker {
    private final Map<SocketChannel, Integer> invalidAttempts = new HashMap<>();

    @Override
    public void increment(SocketChannel channel) {
        Validator.validateNotNull(channel, "channel");

        if (!invalidAttempts.containsKey(channel)) {
            invalidAttempts.put(channel, 1);
        } else {
            int oldAttempts = invalidAttempts.get(channel);
            invalidAttempts.replace(channel, oldAttempts + 1);
        }
    }

    @Override
    public void remove(SocketChannel channel) {
        Validator.validateNotNull(channel, "ip");

        invalidAttempts.remove(channel);
    }

    @Override
    public int getTrackCount(SocketChannel channel) {
        Validator.validateNotNull(channel, "ip");

        if (!invalidAttempts.containsKey(channel)) {
            return 0;
        }

        return invalidAttempts.get(channel);
    }
}
