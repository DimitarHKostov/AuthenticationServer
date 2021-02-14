package com.security.authentication.log;

import com.security.authentication.validator.Validator;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;

public class AuditLog implements Log {
    private final Reader reader;
    private final Writer writer;

    public AuditLog(Reader reader, Writer writer) {
        this.reader = reader;
        this.writer = writer;
    }

    @Override
    public void write(String event) {
        Validator.validateNotNull(event, "event");

        try {
            writer.append(event).flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public Reader read() {
        return this.reader;
    }
}
