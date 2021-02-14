package com.security.authentication.command;

import com.security.authentication.enums.CommandType;

import java.util.List;

public record Command(CommandType type, List<String> parameters) {
}