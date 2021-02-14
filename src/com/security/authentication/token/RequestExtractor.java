package com.security.authentication.token;

import com.security.authentication.enums.ChangeRequest;
import com.security.authentication.validator.Validator;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RequestExtractor {
    public static Map<ChangeRequest, String> extract(List<String> parameters) {
        Validator.validateNotNull(parameters, "parameters");

        if (parameters.size() == 2) {
            return new HashMap<>();
        }

        Map<ChangeRequest, String> result = new HashMap<>();

        for (int i = 2; i < parameters.size() - 1; i += 2) {
            result.put(ChangeRequest.getType(parameters.get(i)), parameters.get(i + 1));
        }

        return result;
    }
}
