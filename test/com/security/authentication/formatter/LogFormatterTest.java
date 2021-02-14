package com.security.authentication.formatter;

import com.security.authentication.enums.LOGInfoStatus;
import com.security.authentication.enums.LOGInfoType;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class LogFormatterTest {
    private static final String IP = "196.124.0.1";

    @Test(expected = IllegalArgumentException.class)
    public void testFormatExpectedIllegalArgumentExceptionWhenTypeNull() {
        LogFormatter.format(null, IP);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFormatExpectedIllegalArgumentExceptionWhenIpNull() {
        LogFormatter.format(LOGInfoType.UNSUCCESSFUL_LOGIN, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFormatExpectedIllegalArgumentExceptionWhenStatusNull() {
        LogFormatter.format(null,
                LOGInfoType.ADDED_ADMIN_PRIVILEGES,
                IP,
                "perpetrator",
                "target",
                true);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFormatExpectedIllegalArgumentExceptionWhenTypeNullMultipleArgs() {
        LogFormatter.format(LOGInfoStatus.BEGIN,
                null,
                IP,
                "perpetrator",
                "target",
                true);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFormatExpectedIllegalArgumentExceptionWhenIpNullMultipleArgs() {
        LogFormatter
                .format(LOGInfoStatus.BEGIN,
                        LOGInfoType.ADDED_ADMIN_PRIVILEGES,
                        null,
                        "perpetrator",
                        "target",
                        true);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFormatExpectedIllegalArgumentExceptionWhenPerpetratorNull() {
        LogFormatter
                .format(LOGInfoStatus.BEGIN,
                        LOGInfoType.ADDED_ADMIN_PRIVILEGES,
                        IP,
                        null,
                        "target",
                        true);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFormatExpectedIllegalArgumentExceptionWhenTargetNull() {
        LogFormatter
                .format(LOGInfoStatus.BEGIN,
                        LOGInfoType.ADDED_ADMIN_PRIVILEGES,
                        IP,
                        "perpetrator",
                        null,
                        true);
    }

    @Test
    public void testFormatFormatFailedToLogDirect() {
        String actual = LogFormatter.format(LOGInfoType.REMOVED_ADMIN_PRIVILEGES, IP);
        String expected = System.lineSeparator() + "<Failed to log>" + System.lineSeparator();

        assertEquals("expecting exact same failed to log", expected, actual);
    }

    @Test
    public void testFormatFormatUnsuccessfulLogIn() {
        String actual = LogFormatter.format(LOGInfoType.UNSUCCESSFUL_LOGIN, IP);
        actual = actual.substring(actual.indexOf("Type"));

        String expected = "Type: Failed log in attempt"
                + System.lineSeparator()
                + "IP: " + IP
                + System.lineSeparator()
                + "........................"
                + System.lineSeparator();

        assertEquals("expecting exact same log", expected, actual);
    }

    @Test
    public void testFormatFailedToLogBegin() {
        String actual = LogFormatter.format(LOGInfoStatus.BEGIN,
                LOGInfoType.UNSUCCESSFUL_LOGIN,
                IP,
                "perpetrator",
                "target",
                true);

        String expected = System.lineSeparator() + "<Failed to log>" + System.lineSeparator();

        assertEquals("expecting exact same failed to log", expected, actual);
    }

    @Test
    public void testFormatFailedToLogEnd() {
        String actual = LogFormatter.format(LOGInfoStatus.END,
                LOGInfoType.UNSUCCESSFUL_LOGIN,
                IP,
                "perpetrator",
                "target",
                true);

        String expected = System.lineSeparator() + "<Failed to log>" + System.lineSeparator();

        assertEquals("expecting exact same failed to log", expected, actual);
    }

    @Test
    public void testFormatAddedAdminPrivilegesBegin() {
        String actual = LogFormatter.format(LOGInfoStatus.BEGIN,
                LOGInfoType.ADDED_ADMIN_PRIVILEGES,
                IP,
                "perpetrator",
                "target",
                true);

        actual = actual.substring(actual.indexOf("Type"));

        String expected = "Type: Configuration change"
                + System.lineSeparator()
                + "Perpetrator: " + "perpetrator" + ", IP: " + IP
                + System.lineSeparator()
                + "Target: " + "target"
                + System.lineSeparator()
                + "Operation: ADD_ADMIN"
                + System.lineSeparator()
                + "........................"
                + System.lineSeparator();

        assertEquals("expecting exact same log", expected, actual);
    }

    @Test
    public void testFormatAddedAdminPrivilegesEndSuccess() {
        String actual = LogFormatter.format(LOGInfoStatus.END,
                LOGInfoType.ADDED_ADMIN_PRIVILEGES,
                IP,
                "perpetrator",
                "target",
                true);

        actual = actual.substring(actual.indexOf("Type"));

        String expected = "Type: Configuration change"
                + System.lineSeparator()
                + "Perpetrator: " + "perpetrator" + ", IP: " + IP
                + System.lineSeparator()
                + "Target: " + "target"
                + System.lineSeparator()
                + "Operation: ADD_ADMIN"
                + System.lineSeparator()
                + "Result: " + "Success"
                + System.lineSeparator()
                + "........................"
                + System.lineSeparator();

        assertEquals("expecting exact same log", expected, actual);
    }

    @Test
    public void testFormatAddedAdminPrivilegesEndFail() {
        String actual = LogFormatter.format(LOGInfoStatus.END,
                LOGInfoType.ADDED_ADMIN_PRIVILEGES,
                IP,
                "perpetrator",
                "target",
                false);

        actual = actual.substring(actual.indexOf("Type"));

        String expected = "Type: Configuration change"
                + System.lineSeparator()
                + "Perpetrator: " + "perpetrator" + ", IP: " + IP
                + System.lineSeparator()
                + "Target: " + "target"
                + System.lineSeparator()
                + "Operation: ADD_ADMIN"
                + System.lineSeparator()
                + "Result: " + "Fail"
                + System.lineSeparator()
                + "........................"
                + System.lineSeparator();

        assertEquals("expecting exact same log", expected, actual);
    }

    @Test
    public void testFormatRemovedAdminPrivilegesBegin() {
        String actual = LogFormatter.format(LOGInfoStatus.BEGIN,
                LOGInfoType.REMOVED_ADMIN_PRIVILEGES,
                IP,
                "perpetrator",
                "target",
                true);

        actual = actual.substring(actual.indexOf("Type"));

        String expected = "Type: Configuration change"
                + System.lineSeparator()
                + "Perpetrator: " + "perpetrator" + ", IP: " + IP
                + System.lineSeparator()
                + "Target: " + "target"
                + System.lineSeparator()
                + "Operation: REMOVE_ADMIN"
                + System.lineSeparator()
                + "........................"
                + System.lineSeparator();

        assertEquals("expecting exact same log", expected, actual);
    }

    @Test
    public void testFormatRemovedAdminPrivilegesEndSuccess() {
        String actual = LogFormatter.format(LOGInfoStatus.END,
                LOGInfoType.REMOVED_ADMIN_PRIVILEGES,
                IP,
                "perpetrator",
                "target",
                true);

        actual = actual.substring(actual.indexOf("Type"));

        String expected = "Type: Configuration change"
                + System.lineSeparator()
                + "Perpetrator: " + "perpetrator" + ", IP: " + IP
                + System.lineSeparator()
                + "Target: " + "target"
                + System.lineSeparator()
                + "Operation: REMOVE_ADMIN"
                + System.lineSeparator()
                + "Result: " + "Success"
                + System.lineSeparator()
                + "........................"
                + System.lineSeparator();

        assertEquals("expecting exact same log", expected, actual);
    }

    @Test
    public void testFormatRemovedAdminPrivilegesEndFail() {
        String actual = LogFormatter.format(LOGInfoStatus.END,
                LOGInfoType.REMOVED_ADMIN_PRIVILEGES,
                IP,
                "perpetrator",
                "target",
                false);

        actual = actual.substring(actual.indexOf("Type"));

        String expected = "Type: Configuration change"
                + System.lineSeparator()
                + "Perpetrator: " + "perpetrator" + ", IP: " + IP
                + System.lineSeparator()
                + "Target: " + "target"
                + System.lineSeparator()
                + "Operation: REMOVE_ADMIN"
                + System.lineSeparator()
                + "Result: " + "Fail"
                + System.lineSeparator()
                + "........................"
                + System.lineSeparator();

        assertEquals("expecting exact same log", expected, actual);
    }
}
