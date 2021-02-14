package com.security.authentication.handler;

import com.security.authentication.generator.Generator;
import com.security.authentication.validator.Validator;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;

public class SessionHandler {
    private final Generator<String> sessionGenerator;
    private final Map<String, LocalDateTime> sessions;
    private static final int SESSION_TIME_TO_LIVE = 10;

    public SessionHandler(Generator<String> generator) {
        this.sessions = new HashMap<>();
        this.sessionGenerator = generator;
    }

    public String generate() {
        String sessionId = sessionGenerator.generate();
        sessions.put(sessionId, LocalDateTime.now());

        return sessionId;
    }

    public boolean isValid(String sessionId) {
        Validator.validateNotNull(sessionId, "sessionId");

        if (!sessions.containsKey(sessionId)) {
            return false;
        }

        LocalDateTime generatedTime = sessions.get(sessionId);

        return Math.abs(ChronoUnit.SECONDS.between(LocalDateTime.now(), generatedTime)) <= SESSION_TIME_TO_LIVE;
    }

    public void invalidate(String sessionId) {
        Validator.validateNotNull(sessionId, "sessionId");

        sessions.remove(sessionId);
    }
}
