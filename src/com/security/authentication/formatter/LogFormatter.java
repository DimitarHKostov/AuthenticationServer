package com.security.authentication.formatter;

import com.security.authentication.enums.LOGInfoStatus;
import com.security.authentication.enums.LOGInfoType;
import com.security.authentication.formatter.subformatters.AddedAdminFormatter;
import com.security.authentication.formatter.subformatters.FailedLogInAttemptFormatter;
import com.security.authentication.formatter.subformatters.RemovedAdminFormatter;
import com.security.authentication.validator.Validator;

public class LogFormatter {
    public static String format(LOGInfoType type, String ip) {
        Validator.validateNotNull(type, "type");
        Validator.validateNotNull(ip, "ip");

        return switch (type) {
            case UNSUCCESSFUL_LOGIN -> FailedLogInAttemptFormatter.format(ip);
            default -> System.lineSeparator() + "<Failed to log>" + System.lineSeparator();
        };
    }

    public static String format(LOGInfoStatus status,
                                LOGInfoType type,
                                String ip,
                                String perpetrator,
                                String target,
                                boolean finalStatus) {
        Validator.validateNotNull(status, "status");
        Validator.validateNotNull(type, "type");
        Validator.validateNotNull(ip, "ip");
        Validator.validateNotNull(perpetrator, "perpetrator");
        Validator.validateNotNull(target, "target");

        return switch (type) {
            case REMOVED_ADMIN_PRIVILEGES -> RemovedAdminFormatter
                    .format(status, ip, perpetrator, target, finalStatus);
            case ADDED_ADMIN_PRIVILEGES -> AddedAdminFormatter
                    .format(status, ip, perpetrator, target, finalStatus);
            default -> System.lineSeparator() + "<Failed to log>" + System.lineSeparator();
        };
    }
}
