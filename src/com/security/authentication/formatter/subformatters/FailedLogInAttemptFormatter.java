package com.security.authentication.formatter.subformatters;

import com.security.authentication.validator.Validator;

import java.time.LocalDateTime;

public class FailedLogInAttemptFormatter {
    public static String format(String ip) {
        Validator.validateNotNull(ip, "ip");

        return "........................"
                + System.lineSeparator()
                + "Timestamp: " + LocalDateTime.now().toString()
                + System.lineSeparator()
                + "Type: Failed log in attempt"
                + System.lineSeparator()
                + "IP: " + ip
                + System.lineSeparator()
                + "........................"
                + System.lineSeparator();
    }
}
