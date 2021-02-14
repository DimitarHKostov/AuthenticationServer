package com.security.authentication.connect;

import com.security.authentication.user.AuthenticatedUser;
import com.security.authentication.validator.Validator;

import java.nio.channels.SocketChannel;
import java.util.HashMap;
import java.util.Map;

public class Connector {
    private final Map<SocketChannel, AuthenticatedUser> userChannels;
    private final Map<SocketChannel, String> connectedSessionIds;

    public Connector() {
        this.userChannels = new HashMap<>();
        this.connectedSessionIds = new HashMap<>();
    }

    public void connect(SocketChannel channel, String sessionId, AuthenticatedUser user) {
        Validator.validateNotNull(channel, "channel");
        Validator.validateNotNull(sessionId, "sessionId");
        Validator.validateNotNull(user, "user");

        userChannels.put(channel, user);
        connectedSessionIds.put(channel, sessionId);
    }

    public void disconnect(SocketChannel channel) {
        Validator.validateNotNull(channel, "channel");

        userChannels.remove(channel);
        connectedSessionIds.remove(channel);
    }

    public boolean isConnected(SocketChannel channel) {
        Validator.validateNotNull(channel, "channel");

        return userChannels.containsKey(channel);
    }

    public String getSession(SocketChannel channel) {
        Validator.validateNotNull(channel, "channel");

        return connectedSessionIds.get(channel);
    }

    public AuthenticatedUser getUser(SocketChannel channel) {
        Validator.validateNotNull(channel, "channel");

        return userChannels.get(channel);
    }
}
