package com.security.authentication.defend.schedule;

import java.nio.channels.SocketChannel;

public interface Scheduler {
    void suspend(SocketChannel channel);

    void release(SocketChannel channel);

    boolean isSuspended(SocketChannel channel);
}
