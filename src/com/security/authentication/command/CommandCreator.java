package com.security.authentication.command;

import com.security.authentication.enums.CommandType;
import com.security.authentication.token.Tokenizer;
import com.security.authentication.validator.Validator;

import java.util.List;

public class CommandCreator {
    public static Command newCommand(String clientInput) {
        Validator.validateNotNull(clientInput, "clientInput");

        if (!clientInput.contains(" ")) {
            return new Command(CommandType.INVALID, null);
        }

        return new Command(CommandType.getType(clientInput), extractArguments(clientInput));
    }

    public static List<String> extractArguments(String clientInput) {
        Validator.validateNotNull(clientInput, "clientInput");

        List<String> tokens = Tokenizer.split(clientInput);
        tokens.remove(0);

        return tokens;
    }
}
