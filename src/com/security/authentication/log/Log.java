package com.security.authentication.log;

import java.io.Reader;

public interface Log {
    void write(String event);

    Reader read();
}
