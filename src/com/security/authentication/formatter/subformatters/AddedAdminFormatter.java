package com.security.authentication.formatter.subformatters;

import com.security.authentication.enums.LOGInfoStatus;
import com.security.authentication.validator.Validator;

import java.time.LocalDateTime;

public class AddedAdminFormatter {
    public static String format(LOGInfoStatus status,
                                String ip,
                                String perpetrator,
                                String target,
                                boolean succeeded) {
        Validator.validateNotNull(status, "status");
        Validator.validateNotNull(ip, "ip");
        Validator.validateNotNull(perpetrator, "perpetrator");
        Validator.validateNotNull(target, "target");

        return switch (status) {
            case BEGIN -> formatBegin(ip, perpetrator, target);
            case END -> formatEnd(ip, perpetrator, target, succeeded);
        };
    }

    private static String formatBegin(String ip, String perpetrator, String target) {
        return "........................"
                + System.lineSeparator()
                + "Timestamp: " + LocalDateTime.now().toString()
                + System.lineSeparator()
                + "Type: Configuration change"
                + System.lineSeparator()
                + "Perpetrator: " + perpetrator + ", IP: " + ip
                + System.lineSeparator()
                + "Target: " + target
                + System.lineSeparator()
                + "Operation: ADD_ADMIN"
                + System.lineSeparator()
                + "........................"
                + System.lineSeparator();
    }

    private static String formatEnd(String ip, String perpetrator, String target, boolean succeeded) {
        return "........................"
                + System.lineSeparator()
                + "Timestamp: " + LocalDateTime.now().toString()
                + System.lineSeparator()
                + "Type: Configuration change"
                + System.lineSeparator()
                + "Perpetrator: " + perpetrator + ", IP: " + ip
                + System.lineSeparator()
                + "Target: " + target
                + System.lineSeparator()
                + "Operation: ADD_ADMIN"
                + System.lineSeparator()
                + "Result: " + (succeeded ? "Success" : "Fail")
                + System.lineSeparator()
                + "........................"
                + System.lineSeparator();
    }
}
