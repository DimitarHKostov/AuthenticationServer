package com.security.authentication.defend.schedule;

import com.security.authentication.validator.Validator;

import java.nio.channels.SocketChannel;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;

public class TemporaryBlockedUserScheduler implements Scheduler {
    private final Map<SocketChannel, LocalDateTime> suspendedChannels = new HashMap<>();
    private static final int IP_SUSPEND_TIME = 15;

    @Override
    public void suspend(SocketChannel channel) {
        Validator.validateNotNull(channel, "channel");

        suspendedChannels.put(channel, LocalDateTime.now());
    }

    @Override
    public void release(SocketChannel channel) {
        Validator.validateNotNull(channel, "channel");

        suspendedChannels.remove(channel);
    }

    @Override
    public boolean isSuspended(SocketChannel channel) {
        Validator.validateNotNull(channel, "channel");

        if (!suspendedChannels.containsKey(channel)) {
            return false;
        }

        LocalDateTime time = suspendedChannels.get(channel);

        if (Math.abs(ChronoUnit.SECONDS.between(LocalDateTime.now(), time)) <= IP_SUSPEND_TIME) {
            return true;
        }

        suspendedChannels.remove(channel);
        return false;
    }
}
