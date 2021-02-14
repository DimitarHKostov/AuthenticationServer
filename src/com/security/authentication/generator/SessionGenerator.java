package com.security.authentication.generator;

import java.util.UUID;

public class SessionGenerator implements Generator<String> {
    @Override
    public String generate() {
        return UUID.randomUUID().toString();
    }
}
