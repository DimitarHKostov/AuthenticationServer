package com.security.authentication.handler;

import com.security.authentication.connect.Connector;
import com.security.authentication.enums.ChangeRequest;
import com.security.authentication.enums.VerificationKey;
import com.security.authentication.exceptions.authorize.AlreadyAuthorizedUserException;
import com.security.authentication.exceptions.authorize.AlreadyNotAuthorizedUserException;
import com.security.authentication.exceptions.authorize.NotAuthorizedUserException;
import com.security.authentication.exceptions.login.AlreadyLoggedInException;
import com.security.authentication.exceptions.login.InvalidCombinationException;
import com.security.authentication.exceptions.login.InvalidSessionIdException;
import com.security.authentication.exceptions.login.NotLoggedInException;
import com.security.authentication.exceptions.register.UserAlreadyRegisteredException;
import com.security.authentication.exceptions.storage.EmptyStorageException;
import com.security.authentication.exceptions.storage.RemoveFailException;
import com.security.authentication.exceptions.storage.StorageFailException;
import com.security.authentication.exceptions.storage.UserNotFoundException;
import com.security.authentication.exceptions.update.NoUpdateRequestException;
import com.security.authentication.exceptions.update.UpdateFailException;
import com.security.authentication.generator.SessionGenerator;
import com.security.authentication.storage.Storage;
import com.security.authentication.token.RequestExtractor;
import com.security.authentication.user.Admin;
import com.security.authentication.user.AuthenticatedUser;
import com.security.authentication.user.RegularUser;
import com.security.authentication.user.User;
import com.security.authentication.user.creator.UserCreator;
import com.security.authentication.validator.Validator;

import java.nio.channels.SocketChannel;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class UserHandler {
    private final SessionHandler sessionHandler;
    private final Map<String, AuthenticatedUser> sessionSemantics;
    private final Connector connector;
    private final Storage storage;

    public UserHandler(Storage storage) {
        this.storage = storage;
        this.sessionHandler = new SessionHandler(new SessionGenerator());
        this.sessionSemantics = new HashMap<>();
        this.connector = new Connector();
    }

    public boolean register(List<String> parameters, SocketChannel channel)
            throws UserAlreadyRegisteredException,
            AlreadyLoggedInException,
            EmptyStorageException,
            StorageFailException {
        Validator.validateNotNull(parameters, "parameters");
        Validator.validateNotNull(channel, "channel");

        checkValidConnection(channel);

        User user = UserCreator.create(parameters);

        if (storage.hasStoredInfo(user)) {
            throw new UserAlreadyRegisteredException("user with that username already exists");
        }

        if (storage.isEmpty()) {
            storage.add(new Admin(user.getAccountInfo(), user.getPersonalInfo()));
            throw new EmptyStorageException("empty storage");
        }

        storage.add(user);

        return true;
    }

    public String logIn(List<String> parameters, SocketChannel channel)
            throws InvalidCombinationException,
            InvalidSessionIdException,
            AlreadyLoggedInException,
            StorageFailException {
        Validator.validateNotNull(parameters, "parameters");
        Validator.validateNotNull(channel, "channel");

        if (VerificationKey.getType(parameters.get(0)) == VerificationKey.SESSION_ID) {
            return logInWithSession(parameters, channel);
        }

        return logInWithCombination(parameters, channel);
    }

    public boolean logOut(List<String> parameters, SocketChannel channel)
            throws NotLoggedInException,
            InvalidSessionIdException {
        Validator.validateNotNull(parameters, "parameters");
        Validator.validateNotNull(channel, "channel");

        checkExpiredSessionId(channel);

        if (!connector.isConnected(channel)) {
            throw new NotLoggedInException("not logged in");
        }

        String inputSessionId = parameters.get(1);
        String actualSessionId = connector.getSession(channel);

        if (sessionHandler.isValid(actualSessionId) && !sessionHandler.isValid(inputSessionId)) {
            throw new InvalidSessionIdException("session is invalid");
        }

        connector.disconnect(channel);
        sessionSemantics.remove(actualSessionId);

        return true;
    }

    public boolean updateAccountPassword(List<String> parameters, SocketChannel channel)
            throws NotLoggedInException,
            InvalidCombinationException,
            InvalidSessionIdException,
            StorageFailException {
        Validator.validateNotNull(parameters, "parameters");
        Validator.validateNotNull(channel, "channel");

        checkExpiredSessionId(channel);

        String sessionId = parameters.get(1);

        if (!connector.isConnected(channel)) {
            throw new NotLoggedInException("not logged in");
        }

        if (!sessionHandler.isValid(sessionId)) {
            throw new InvalidSessionIdException("session is invalid");
        }

        String username = parameters.get(3);
        String oldPassword = parameters.get(5);

        AuthenticatedUser user = connector.getUser(channel);

        if (!user.getAccountInfo().getUsername().equals(username)
                || !user.getAccountInfo().getPassword().equals(oldPassword)) {
            throw new InvalidCombinationException("invalid username/password");
        }

        String newPassword = parameters.get(7);

        try {
            storage.update(user, Map.of(ChangeRequest.NEW_PASSWORD, newPassword));
        } catch (UpdateFailException | NoUpdateRequestException e) {
            throw new StorageFailException("storage failed");
        }

        return true;
    }

    public boolean updatePersonalInfo(List<String> parameters, SocketChannel channel)
            throws InvalidSessionIdException,
            NotLoggedInException,
            StorageFailException,
            NoUpdateRequestException {
        Validator.validateNotNull(parameters, "parameters");
        Validator.validateNotNull(channel, "channel");

        checkExpiredSessionId(channel);

        if (!connector.isConnected(channel)) {
            throw new NotLoggedInException("not logged in");
        }

        String sessionId = parameters.get(1);

        if (!sessionHandler.isValid(sessionId)) {
            throw new InvalidSessionIdException("session is invalid");
        }

        try {
            storage.update(connector.getUser(channel), RequestExtractor.extract(parameters));
        } catch (UpdateFailException e) {
            throw new StorageFailException("storage failed");
        }

        return true;
    }

    public boolean makeAdmin(List<String> parameters, SocketChannel channel)
            throws UserNotFoundException,
            NotAuthorizedUserException,
            AlreadyAuthorizedUserException,
            StorageFailException,
            NotLoggedInException,
            InvalidSessionIdException {
        Validator.validateNotNull(parameters, "parameters");
        Validator.validateNotNull(channel, "channel");

        checkExpiredSessionId(channel);

        if (!connector.isConnected(channel)) {
            throw new NotLoggedInException("not logged in");
        }

        String sessionId = parameters.get(1);

        if (!sessionHandler.isValid(sessionId)) {
            throw new InvalidSessionIdException("session is invalid");
        }

        User admin = storage.extract(connector.getUser(channel).getAccountInfo().getUsername());

        if (!admin.isAuthorized()) {
            throw new NotAuthorizedUserException("not admin");
        }

        String username = parameters.get(3);

        User user = storage.extract(username);

        if (user.isAuthorized()) {
            throw new AlreadyAuthorizedUserException("user is already admin");
        }

        try {
            storage.remove(user);
        } catch (RemoveFailException e) {
            throw new StorageFailException("storage failed");
        }

        return storage.add(new Admin(user.getAccountInfo(), user.getPersonalInfo()));
    }

    public boolean removeAdmin(List<String> parameters, SocketChannel channel)
            throws UserNotFoundException,
            NotAuthorizedUserException,
            StorageFailException,
            AlreadyNotAuthorizedUserException,
            NotLoggedInException,
            InvalidSessionIdException {
        Validator.validateNotNull(parameters, "parameters");
        Validator.validateNotNull(channel, "channel");

        checkExpiredSessionId(channel);

        if (!connector.isConnected(channel)) {
            throw new NotLoggedInException("not logged in");
        }

        String sessionId = parameters.get(1);

        if (!sessionHandler.isValid(sessionId)) {
            throw new InvalidSessionIdException("session is invalid");
        }

        User admin = storage.extract(connector.getUser(channel).getAccountInfo().getUsername());

        if (!admin.isAuthorized()) {
            throw new NotAuthorizedUserException("not admin");
        }

        String username = parameters.get(3);
        User user = storage.extract(username);

        if (!user.isAuthorized()) {
            throw new AlreadyNotAuthorizedUserException("user already not authorized");
        }

        try {
            storage.remove(user);
        } catch (RemoveFailException e) {
            throw new StorageFailException("storage failed");
        }

        return storage.add(new RegularUser(user.getAccountInfo(), user.getPersonalInfo()));
    }

    public boolean isLoggedIn(SocketChannel channel) {
        Validator.validateNotNull(channel, "channel");

        return connector.isConnected(channel);
    }

    public boolean isSessionValid(String sessionId) {
        Validator.validateNotNull(sessionId, "sessionId");

        return sessionHandler.isValid(sessionId);
    }

    public boolean removeUser(List<String> parameters, SocketChannel channel)
            throws UserNotFoundException,
            NotLoggedInException,
            NotAuthorizedUserException,
            InvalidSessionIdException,
            StorageFailException {
        Validator.validateNotNull(parameters, "parameters");
        Validator.validateNotNull(channel, "channel");

        checkExpiredSessionId(channel);

        if (!connector.isConnected(channel)) {
            throw new NotLoggedInException("not logged in");
        }

        String sessionId = parameters.get(1);

        if (!sessionHandler.isValid(sessionId)) {
            throw new InvalidSessionIdException("session is invalid");
        }

        User admin = storage.extract(connector.getUser(channel).getAccountInfo().getUsername());

        if (!admin.isAuthorized()) {
            throw new NotAuthorizedUserException("not admin");
        }

        String username = parameters.get(3);
        try {
            storage.remove(storage.extract(username));
        } catch (RemoveFailException e) {
            throw new StorageFailException("failed to delete user");
        }

        sessionHandler.invalidate(sessionId);

        return true;
    }

    public User extract(SocketChannel channel) {
        Validator.validateNotNull(channel, "channel");

        return connector.getUser(channel);
    }

    private String logInWithSession(List<String> parameters, SocketChannel channel)
            throws InvalidSessionIdException,
            AlreadyLoggedInException {
        checkValidConnection(channel);

        String sessionId = parameters.get(1);

        if (!sessionHandler.isValid(sessionId)) {
            throw new InvalidSessionIdException("session is invalid");
        }

        AuthenticatedUser user = sessionSemantics.get(sessionId);

        connector.connect(channel, sessionId, user);
        sessionSemantics.put(sessionId, user);

        return sessionId;
    }

    private String logInWithCombination(List<String> parameters, SocketChannel channel)
            throws InvalidCombinationException,
            AlreadyLoggedInException,
            StorageFailException {

        checkValidConnection(channel);

        String username = parameters.get(1);
        User user;

        try {
            user = storage.extract(username);
        } catch (UserNotFoundException e) {
            throw new InvalidCombinationException("invalid combination");
        }

        if (user.isAuthorized()) {
            user = new Admin(user.getAccountInfo(), user.getPersonalInfo());
        } else {
            user = new RegularUser(user.getAccountInfo(), user.getPersonalInfo());
        }

        String password = parameters.get(3);

        if (!password.equals(user.getAccountInfo().getPassword())) {
            throw new InvalidCombinationException("invalid combination");
        }

        String newSessionId = sessionHandler.generate();

        connector.disconnect(channel);
        connector.connect(channel, newSessionId, (AuthenticatedUser) user);
        sessionSemantics.put(newSessionId, (AuthenticatedUser) user);

        return newSessionId;
    }

    private void checkValidConnection(SocketChannel channel) throws AlreadyLoggedInException {
        if (connector.isConnected(channel)) {
            String sessionId = connector.getSession(channel);
            if (sessionHandler.isValid(sessionId)) {
                throw new AlreadyLoggedInException("already logged in");
            } else {
                sessionHandler.invalidate(sessionId);
                connector.disconnect(channel);
            }
        }
    }

    private void checkExpiredSessionId(SocketChannel channel) throws NotLoggedInException {
        if (connector.isConnected(channel)) {
            String sessionId = connector.getSession(channel);
            if (!sessionHandler.isValid(sessionId)) {
                connector.disconnect(channel);
                sessionHandler.invalidate(sessionId);
                throw new NotLoggedInException("not logged in");
            }
        }
    }
}