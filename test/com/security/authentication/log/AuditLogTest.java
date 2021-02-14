package com.security.authentication.log;

import org.junit.BeforeClass;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

import static org.junit.Assert.assertEquals;

public class AuditLogTest {
    private static Log auditLog;
    private static File file;

    @BeforeClass
    public static void setUp() throws IOException {
        file = File.createTempFile("frontHaha", "endHaha");
        auditLog = new AuditLog(new BufferedReader(new FileReader(file.toString())),
                new BufferedWriter(new FileWriter(file.toString(), true)));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWriteExpectedIllegalArgumentException() {
        auditLog.write(null);
    }

    @Test
    public void testReadExpectedExactResult() throws IOException {
        String firstLine = "user123" + System.lineSeparator();
        String secondLine = "user456";
        String[] lines = {"user123", secondLine};
        int i = 0;

        auditLog.write(firstLine);
        auditLog.write(secondLine);

        String line;

        try (var r = new BufferedReader(new FileReader(file.toString()))) {
            while ((line = r.readLine()) != null) {
                assertEquals("expecting same lines", lines[i], line);
                i++;
            }
        }
    }
}
