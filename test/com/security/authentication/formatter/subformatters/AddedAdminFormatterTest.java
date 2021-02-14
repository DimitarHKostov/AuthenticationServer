package com.security.authentication.formatter.subformatters;

import com.security.authentication.enums.LOGInfoStatus;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class AddedAdminFormatterTest {
    private static final String IP = "196.124.0.1";

    @Test(expected = IllegalArgumentException.class)
    public void testFormatExpectedIllegalArgumentExceptionWhenStatusNull() {
        AddedAdminFormatter.format(null,
                IP,
                "perpetrator",
                "target",
                true);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFormatExpectedIllegalArgumentExceptionWhenIpNull() {
        AddedAdminFormatter.format(LOGInfoStatus.BEGIN,
                null,
                "perpetrator",
                "target",
                true);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFormatExpectedIllegalArgumentExceptionWhenPerpetratorNull() {
        AddedAdminFormatter.format(LOGInfoStatus.BEGIN,
                IP,
                null,
                "target",
                true);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFormatExpectedIllegalArgumentExceptionWhenTargetNull() {
        AddedAdminFormatter.format(LOGInfoStatus.BEGIN,
                IP,
                "perpetrator",
                null,
                true);
    }

    @Test
    public void testFormatStatusBegin() {
        String actual = AddedAdminFormatter.format(LOGInfoStatus.BEGIN,
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
    public void testFormatStatusEndSuccess() {
        String actual = AddedAdminFormatter.format(LOGInfoStatus.END,
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
    public void testFormatStatusEndFail() {
        String actual = AddedAdminFormatter.format(LOGInfoStatus.END,
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
}
