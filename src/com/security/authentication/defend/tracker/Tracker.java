package com.security.authentication.defend.tracker;

import java.nio.channels.SocketChannel;

public interface Tracker {
    void increment(SocketChannel channel);

    void remove(SocketChannel channel);

    int getTrackCount(SocketChannel channel);
}
