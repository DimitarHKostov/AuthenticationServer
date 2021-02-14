package com.security.authentication.token;

import com.security.authentication.validator.Validator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Tokenizer {
    public static List<String> split(String command) {
        Validator.validateNotNull(command, "command");

        if (!command.contains(" ")) {
            return List.of(command);
        }

        String[] tokens = command.split(" ");

        return new ArrayList<>(Arrays.asList(tokens));
    }
}
