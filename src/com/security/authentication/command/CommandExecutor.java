package com.security.authentication.command;

import com.security.authentication.defend.Defender;
import com.security.authentication.enums.LOGInfoStatus;
import com.security.authentication.enums.LOGInfoType;
import com.security.authentication.exceptions.authorize.AlreadyAuthorizedUserException;
import com.security.authentication.exceptions.authorize.AlreadyNotAuthorizedUserException;
import com.security.authentication.exceptions.authorize.NotAuthorizedUserException;
import com.security.authentication.exceptions.login.AlreadyLoggedInException;
import com.security.authentication.exceptions.login.InvalidCombinationException;
import com.security.authentication.exceptions.login.InvalidSessionIdException;
import com.security.authentication.exceptions.login.NotLoggedInException;
import com.security.authentication.exceptions.register.UserAlreadyRegisteredException;
import com.security.authentication.exceptions.server.IPGetFailException;
import com.security.authentication.exceptions.storage.EmptyStorageException;
import com.security.authentication.exceptions.storage.StorageFailException;
import com.security.authentication.exceptions.storage.UserNotFoundException;
import com.security.authentication.exceptions.update.NoUpdateRequestException;
import com.security.authentication.formatter.LogFormatter;
import com.security.authentication.handler.UserHandler;
import com.security.authentication.log.Log;
import com.security.authentication.validator.Validator;

import java.io.IOException;
import java.nio.channels.SocketChannel;

public class CommandExecutor {
    private final UserHandler userHandler;
    private final Defender defender;
    private final Log log;

    public CommandExecutor(Log log, UserHandler userHandler, Defender defender) {
        this.log = log;
        this.userHandler = userHandler;
        this.defender = defender;
    }

    public String execute(Command command, SocketChannel channel) {
        try {
            Validator.validateNotNull(command, "command");
            Validator.validateNotNull(channel, "channel");
        } catch (IllegalArgumentException e) {
            return "<A problem in the system has occurred, please try again>";
        }

        return switch (command.type()) {
            case REGISTER -> handleRegister(command, channel);
            case LOGIN -> handleLogIn(command, channel);
            case UPDATE_USER -> handleUpdateUser(command, channel);
            case RESET_PASSWORD -> handleResetPassword(command, channel);
            case LOGOUT -> handleLogOut(command, channel);
            case ADD_ADMIN_USER -> handleAddAdmin(command, channel);
            case REMOVE_ADMIN_USER -> handleRemoveAdmin(command, channel);
            case DELETE_USER -> handleDeleteUser(command, channel);
            case INVALID -> handleUnknown();
        };
    }

    private String handleUnknown() {
        return "<Unknown command>";
    }

    private String handleRegister(Command command, SocketChannel channel) {
        String responseValidationFail = Validator.validateCommand(command);
        if (responseValidationFail != null) {
            return responseValidationFail;
        }

        if (defender.isBlocked(channel)) {
            return "<You are currently blocked>";
        }

        try {
            userHandler.register(command.parameters(), channel);
        } catch (UserAlreadyRegisteredException e) {
            return "<Username is taken, choose another one>";
        } catch (AlreadyLoggedInException e) {
            return "<You are logged in>";
        } catch (StorageFailException e) {
            return "<A problem in the system has occurred, please try again>";
        } catch (EmptyStorageException e) {
            return "<You have been successfully registered. Since you are the first user in the system, you are admin>";
        }

        defender.clearHistory(channel);

        return "<You have been successfully registered>";
    }

    private String handleLogIn(Command command, SocketChannel channel) {
        String responseValidationFail = Validator.validateCommand(command);
        if (responseValidationFail != null) {
            return responseValidationFail;
        }

        if (defender.isBlocked(channel)) {
            return "<You are currently blocked>";
        }

        String sessionId;

        try {
            sessionId = userHandler.logIn(command.parameters(), channel);
        } catch (InvalidCombinationException e) {
            defender.registerInvalidTry(channel);
            toLog(LOGInfoType.UNSUCCESSFUL_LOGIN, channel);
            return "<Wrong username/password combination>";
        } catch (InvalidSessionIdException e) {
            defender.registerInvalidTry(channel);
            toLog(LOGInfoType.UNSUCCESSFUL_LOGIN, channel);
            return "<Wrong session id>";
        } catch (AlreadyLoggedInException e) {
            return "<You are already logged in>";
        } catch (StorageFailException e) {
            return "<A problem in the system has occurred, please try again>";
        }

        return "<You have been successfully logged in, your session id is <" + sessionId + ">>";
    }

    private String handleUpdateUser(Command command, SocketChannel channel) {
        String responseValidationFail = Validator.validateCommand(command);
        if (responseValidationFail != null) {
            return responseValidationFail;
        }

        try {
            userHandler.updatePersonalInfo(command.parameters(), channel);
        } catch (InvalidSessionIdException e) {
            return "<Wrong session id>";
        } catch (NotLoggedInException e) {
            return "<You are not logged in>";
        } catch (StorageFailException e) {
            return "<A problem in the system has occurred, please try again>";
        } catch (NoUpdateRequestException e) {
            return "<You did not request any changes>";
        }

        return "<You successfully updated your profile>";
    }

    private String handleResetPassword(Command command, SocketChannel channel) {
        String response = Validator.validateCommand(command);
        if (response != null) {
            return response;
        }

        try {
            userHandler.updateAccountPassword(command.parameters(), channel);
        } catch (NotLoggedInException e) {
            return "<You are not logged in>";
        } catch (InvalidCombinationException e) {
            return "<Wrong username/password combination>";
        } catch (InvalidSessionIdException e) {
            return "<Wrong session id>";
        } catch (StorageFailException e) {
            return "<A problem in the system has occurred, please try again>";
        }

        return "<You successfully changed your password to <" + command.parameters().get(7) + ">>";
    }

    private String handleLogOut(Command command, SocketChannel channel) {
        String responseValidationFail = Validator.validateCommand(command);
        if (responseValidationFail != null) {
            return responseValidationFail;
        }

        try {
            userHandler.logOut(command.parameters(), channel);
        } catch (NotLoggedInException e) {
            return "<You are not logged in>";
        } catch (InvalidSessionIdException e) {
            return "<Wrong session id>";
        }

        return "<You logged out successfully>";
    }

    private String handleAddAdmin(Command command, SocketChannel channel) {
        String responseValidationFail = Validator.validateCommand(command);
        if (responseValidationFail != null) {
            return responseValidationFail;
        }

        if (!userHandler.isLoggedIn(channel)) {
            return "<You are not logged in>";
        }

        String sessionId = command.parameters().get(1);

        if (!userHandler.isSessionValid(sessionId)) {
            return "<Wrong session id>";
        }

        String perpetrator = userHandler.extract(channel).getAccountInfo().getUsername();
        String target = command.parameters().get(3);
        toLog(LOGInfoStatus.BEGIN, LOGInfoType.ADDED_ADMIN_PRIVILEGES, channel, perpetrator, target, false);

        try {
            userHandler.makeAdmin(command.parameters(), channel);
        } catch (UserNotFoundException e) {
            toLog(LOGInfoStatus.END, LOGInfoType.ADDED_ADMIN_PRIVILEGES, channel, perpetrator, target, false);
            return "<User with username <" + command.parameters().get(3) + "> does not exist>";
        } catch (NotAuthorizedUserException e) {
            toLog(LOGInfoStatus.END, LOGInfoType.ADDED_ADMIN_PRIVILEGES, channel, perpetrator, target, false);
            return "<Only a admin can add new admin>";
        } catch (AlreadyAuthorizedUserException e) {
            toLog(LOGInfoStatus.END, LOGInfoType.ADDED_ADMIN_PRIVILEGES, channel, perpetrator, target, false);
            return "<User with username <" + command.parameters().get(3) + "> is already admin>";
        } catch (StorageFailException e) {
            toLog(LOGInfoStatus.END, LOGInfoType.ADDED_ADMIN_PRIVILEGES, channel, perpetrator, target, false);
            return "<A problem in the system has occurred, please try again>";
        } catch (NotLoggedInException e) {
            return "<You are not logged in>";
        } catch (InvalidSessionIdException e) {
            return "<Wrong session id>";
        }

        toLog(LOGInfoStatus.END, LOGInfoType.ADDED_ADMIN_PRIVILEGES, channel, perpetrator, target, true);

        return "<You successfully added new admin to the system>";
    }

    private String handleRemoveAdmin(Command command, SocketChannel channel) {
        String responseValidationFail = Validator.validateCommand(command);
        if (responseValidationFail != null) {
            return responseValidationFail;
        }

        if (!userHandler.isLoggedIn(channel)) {
            return "<You are not logged in>";
        }

        String sessionId = command.parameters().get(1);

        if (!userHandler.isSessionValid(sessionId)) {
            return "<Wrong session id>";
        }

        String perpetrator = userHandler.extract(channel).getAccountInfo().getUsername();
        String target = command.parameters().get(3);
        toLog(LOGInfoStatus.BEGIN, LOGInfoType.REMOVED_ADMIN_PRIVILEGES, channel, perpetrator, target, false);

        try {
            userHandler.removeAdmin(command.parameters(), channel);
        } catch (NotAuthorizedUserException e) {
            toLog(LOGInfoStatus.END, LOGInfoType.REMOVED_ADMIN_PRIVILEGES, channel, perpetrator, target, false);
            return "<Only a admin can remove admin>";
        } catch (UserNotFoundException e) {
            toLog(LOGInfoStatus.END, LOGInfoType.REMOVED_ADMIN_PRIVILEGES, channel, perpetrator, target, false);
            return "<User with username <" + command.parameters().get(3) + "> does not exist>";
        } catch (StorageFailException e) {
            toLog(LOGInfoStatus.END, LOGInfoType.REMOVED_ADMIN_PRIVILEGES, channel, perpetrator, target, false);
            return "<A problem in the system has occurred, please try again>";
        } catch (AlreadyNotAuthorizedUserException e) {
            toLog(LOGInfoStatus.END, LOGInfoType.REMOVED_ADMIN_PRIVILEGES, channel, perpetrator, target, false);
            return "<User with username <" + command.parameters().get(3) + "> is not admin>";
        } catch (NotLoggedInException e) {
            return "<You are not logged in>";
        } catch (InvalidSessionIdException e) {
            return "<Wrong session id>";
        }

        toLog(LOGInfoStatus.END, LOGInfoType.REMOVED_ADMIN_PRIVILEGES, channel, perpetrator, target, true);

        return "<You removed a admin successfully>";
    }

    private String handleDeleteUser(Command command, SocketChannel channel) {
        String responseValidationFail = Validator.validateCommand(command);

        if (responseValidationFail != null) {
            return responseValidationFail;
        }

        if (!userHandler.isLoggedIn(channel)) {
            return "<You are not logged in>";
        }

        String sessionId = command.parameters().get(1);

        if (!userHandler.isSessionValid(sessionId)) {
            return "<Wrong session id>";
        }

        try {
            userHandler.removeUser(command.parameters(), channel);
        } catch (NotLoggedInException e) {
            return "<You are not logged in>";
        } catch (InvalidSessionIdException e) {
            return "<Wrong session id>";
        } catch (NotAuthorizedUserException e) {
            return "<Only a admin can remove user>";
        } catch (UserNotFoundException e) {
            return "<User with username <" + command.parameters().get(3) + "> does not exist>";
        } catch (StorageFailException e) {
            return "<A problem in the system has occurred, please try again>";
        }

        return "<You deleted a user successfully>";
    }

    private void toLog(LOGInfoStatus status,
                       LOGInfoType type,
                       SocketChannel channel,
                       String perpetrator,
                       String target,
                       boolean succeeded) {

        String ip = getUserIp(channel);
        log.write(LogFormatter.format(status, type, ip, perpetrator, target, succeeded));
    }

    private void toLog(LOGInfoType type, SocketChannel channel) {
        String ip = getUserIp(channel);
        log.write(LogFormatter.format(type, ip));
    }

    private String getUserIp(SocketChannel channel) {
        String remoteUserInfo;

        try {
            remoteUserInfo = channel.getRemoteAddress().toString();
        } catch (IOException e) {
            throw new IPGetFailException("could not retrieve user ip", e);
        }

        return remoteUserInfo.substring(1, remoteUserInfo.indexOf(":"));
    }
}
