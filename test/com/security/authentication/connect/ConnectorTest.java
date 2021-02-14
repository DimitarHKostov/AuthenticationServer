package com.security.authentication.connect;

import com.security.authentication.user.AuthenticatedUser;
import com.security.authentication.user.User;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.nio.channels.SocketChannel;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(MockitoJUnitRunner.class)
public class ConnectorTest {
    private final Connector connector = new Connector();

    @Mock
    private SocketChannel socketChannel;

    private final String sessionId = "session-id";

    @Mock
    private AuthenticatedUser authenticatedUser;

    @Test(expected = IllegalArgumentException.class)
    public void testConnectExpectedIllegalArgumentExceptionWhenChannelNull() {
        connector.connect(null, sessionId, authenticatedUser);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConnectExpectedIllegalArgumentExceptionWhenSessionNull() {
        connector.connect(socketChannel, null, authenticatedUser);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConnectExpectedIllegalArgumentExceptionWhenUserNull() {
        connector.connect(socketChannel, sessionId, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDisconnectExpectedIllegalArgumentException() {
        connector.disconnect(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testIsConnectedExpectedIllegalArgumentException() {
        connector.isConnected(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetSessionExpectedIllegalArgumentException() {
        connector.getSession(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetUserExpectedIllegalArgumentException() {
        connector.getUser(null);
    }

    @Test
    public void testConnectExpectedSuccess() {
        assertFalse(connector.isConnected(socketChannel));

        connector.connect(socketChannel, sessionId, authenticatedUser);

        assertTrue(connector.isConnected(socketChannel));
    }

    @Test
    public void testDisconnectExpectedSuccess() {
        connector.connect(socketChannel, sessionId, authenticatedUser);
        assertTrue(connector.isConnected(socketChannel));

        connector.disconnect(socketChannel);
        assertFalse(connector.isConnected(socketChannel));
    }

    @Test
    public void testGetSessionExpectedSuccess() {
        connector.connect(socketChannel, sessionId, authenticatedUser);

        String actualSessionId = connector.getSession(socketChannel);
        assertEquals("expecting same session id", sessionId, actualSessionId);
    }

    @Test
    public void testGetUserExpectedSuccess() {
        connector.connect(socketChannel, sessionId, authenticatedUser);

        User actualUser = connector.getUser(socketChannel);
        assertEquals("expecting same user", authenticatedUser, actualUser);
    }
}
