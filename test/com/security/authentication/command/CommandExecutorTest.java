package com.security.authentication.command;

import com.security.authentication.defend.Defender;
import com.security.authentication.enums.CommandType;
import com.security.authentication.exceptions.authorize.AlreadyAuthorizedUserException;
import com.security.authentication.exceptions.authorize.AlreadyNotAuthorizedUserException;
import com.security.authentication.exceptions.authorize.NotAuthorizedUserException;
import com.security.authentication.exceptions.login.AlreadyLoggedInException;
import com.security.authentication.exceptions.login.InvalidCombinationException;
import com.security.authentication.exceptions.login.InvalidSessionIdException;
import com.security.authentication.exceptions.login.NotLoggedInException;
import com.security.authentication.exceptions.register.UserAlreadyRegisteredException;
import com.security.authentication.exceptions.storage.EmptyStorageException;
import com.security.authentication.exceptions.storage.StorageFailException;
import com.security.authentication.exceptions.storage.UserNotFoundException;
import com.security.authentication.exceptions.update.NoUpdateRequestException;
import com.security.authentication.handler.UserHandler;
import com.security.authentication.log.Log;
import com.security.authentication.user.UnauthenticatedUser;
import com.security.authentication.user.info.AccountInfo;
import com.security.authentication.user.info.PersonalInfo;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.channels.SocketChannel;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class CommandExecutorTest {
    private static final String REMOTE_USER_INFO = "/127.0.0.1:52560";

    @Mock
    private Log log;

    @Mock
    private UserHandler userHandler;

    @Mock
    private Defender defender;

    @InjectMocks
    private CommandExecutor commandExecutor;

    @Mock
    private SocketChannel channel;

    @Mock
    private SocketAddress socketAddress;

    @Test
    public void testExecuteExpectedServerProblemResponseWhenCommandIsNull() {
        String actual = commandExecutor.execute(null, channel);
        String expected = "<A problem in the system has occurred, please try again>";

        assertEquals("expecting exact same answer", expected, actual);
    }

    @Test
    public void testExecuteExpectedServerProblemResponseWhenChannelIsNull() {
        String actual = commandExecutor.execute(new Command(CommandType.REGISTER, List.of("Asd")), null);
        String expected = "<A problem in the system has occurred, please try again>";

        assertEquals("expecting exact same answer", expected, actual);
    }

    @Test
    public void testExecuteRegisterExpectedMissingSentinelOrData() {
        String actual = commandExecutor.execute(new Command(CommandType.REGISTER, List.of("--username", "user",
                "-password", "pass",
                "--first-name", "fname",
                "--last-name", "lname",
                "--email", "email")), channel);

        String expected = "<Missing authentication sentinel/data>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteRegisterExpectedInvalidNumberOfArguments() {
        String actual = commandExecutor.execute(new Command(CommandType.REGISTER, List.of("--username", "user",
                "-password", "pass",
                "--first-name", "fname",
                "--last-name", "lname")), channel);

        String expected = "<Wrong number of arguments>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteRegisterExpectedBlocked() {
        when(defender.isBlocked(any())).thenReturn(true);

        String actual = commandExecutor.execute(new Command(CommandType.REGISTER, List.of("--username", "user",
                "--password", "pass",
                "--first-name", "fname",
                "--last-name", "lname",
                "--email", "email")), channel);

        String expected = "<You are currently blocked>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteRegisterExpectedUsernameTaken()
            throws UserAlreadyRegisteredException,
            AlreadyLoggedInException,
            EmptyStorageException,
            StorageFailException {
        when(defender.isBlocked(any())).thenReturn(false);
        when(userHandler.register(any(), any())).thenThrow(UserAlreadyRegisteredException.class);

        String actual = commandExecutor.execute(new Command(CommandType.REGISTER, List.of("--username", "user",
                "--password", "pass",
                "--first-name", "fname",
                "--last-name", "lname",
                "--email", "email")), channel);

        String expected = "<Username is taken, choose another one>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteRegisterExpectedAlreadyLoggedIn()
            throws UserAlreadyRegisteredException,
            AlreadyLoggedInException,
            EmptyStorageException,
            StorageFailException {
        when(defender.isBlocked(any())).thenReturn(false);
        when(userHandler.register(any(), any())).thenThrow(AlreadyLoggedInException.class);

        String actual = commandExecutor.execute(new Command(CommandType.REGISTER, List.of("--username", "user",
                "--password", "pass",
                "--first-name", "fname",
                "--last-name", "lname",
                "--email", "email")), channel);

        String expected = "<You are logged in>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteRegisterExpectedServerProblemWithStorage()
            throws UserAlreadyRegisteredException,
            AlreadyLoggedInException,
            EmptyStorageException,
            StorageFailException {
        when(defender.isBlocked(any())).thenReturn(false);
        when(userHandler.register(any(), any())).thenThrow(StorageFailException.class);

        String actual = commandExecutor.execute(new Command(CommandType.REGISTER, List.of("--username", "user",
                "--password", "pass",
                "--first-name", "fname",
                "--last-name", "lname",
                "--email", "email")), channel);

        String expected = "<A problem in the system has occurred, please try again>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteRegisterExpectedEmptyStorage()
            throws UserAlreadyRegisteredException,
            AlreadyLoggedInException,
            EmptyStorageException,
            StorageFailException {
        when(defender.isBlocked(any())).thenReturn(false);
        when(userHandler.register(any(), any())).thenThrow(EmptyStorageException.class);

        String actual = commandExecutor.execute(new Command(CommandType.REGISTER, List.of("--username", "user",
                "--password", "pass",
                "--first-name", "fname",
                "--last-name", "lname",
                "--email", "email")), channel);

        String expected =
                "<You have been successfully registered. Since you are the first user in the system, you are admin>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteRegisterExpectedSuccess()
            throws UserAlreadyRegisteredException,
            AlreadyLoggedInException,
            EmptyStorageException,
            StorageFailException {
        when(defender.isBlocked(any())).thenReturn(false);
        when(userHandler.register(any(), any())).thenReturn(true);

        String actual = commandExecutor.execute(new Command(CommandType.REGISTER, List.of("--username", "user",
                "--password", "pass",
                "--first-name", "fname",
                "--last-name", "lname",
                "--email", "email")), channel);

        String expected = "<You have been successfully registered>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteLogInExpectedMissingSentinelOrData() {
        String actual = commandExecutor.execute(new Command(CommandType.LOGIN, List.of("--username", "user",
                "-password", "pass")), channel);

        String expected = "<Missing authentication sentinel/data>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteLogInExpectedInvalidNumberOfArguments() {
        String actual = commandExecutor
                .execute(new Command(CommandType.REGISTER, List.of("--username", "user")), channel);

        String expected = "<Wrong number of arguments>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteLogInExpectedBlocked() {
        when(defender.isBlocked(any())).thenReturn(true);

        String actual = commandExecutor.execute(new Command(CommandType.LOGIN, List.of("--username", "user",
                "--password", "pass")), channel);

        String expected = "<You are currently blocked>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteLogInExpectedInvalidCombination()
            throws AlreadyLoggedInException,
            StorageFailException,
            InvalidCombinationException,
            InvalidSessionIdException,
            IOException {
        when(defender.isBlocked(any())).thenReturn(false);
        when(userHandler.logIn(any(), any())).thenThrow(InvalidCombinationException.class);
        when(channel.getRemoteAddress()).thenReturn(socketAddress);
        when(channel.getRemoteAddress().toString()).thenReturn(REMOTE_USER_INFO);

        String actual = commandExecutor.execute(new Command(CommandType.LOGIN, List.of("--username", "user",
                "--password", "pass")), channel);

        String expected = "<Wrong username/password combination>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteLogInExpectedInvalidSession()
            throws AlreadyLoggedInException,
            StorageFailException,
            InvalidCombinationException,
            InvalidSessionIdException,
            IOException {
        when(defender.isBlocked(any())).thenReturn(false);
        when(userHandler.logIn(any(), any())).thenThrow(InvalidSessionIdException.class);
        when(channel.getRemoteAddress()).thenReturn(socketAddress);
        when(channel.getRemoteAddress().toString()).thenReturn(REMOTE_USER_INFO);

        String actual = commandExecutor.execute(new Command(CommandType.LOGIN, List.of("--username", "user",
                "--password", "pass")), channel);

        String expected = "<Wrong session id>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteLogInExpectedAlreadyLoggedIn()
            throws AlreadyLoggedInException,
            StorageFailException,
            InvalidCombinationException,
            InvalidSessionIdException {
        when(defender.isBlocked(any())).thenReturn(false);
        when(userHandler.logIn(any(), any())).thenThrow(AlreadyLoggedInException.class);

        String actual = commandExecutor.execute(new Command(CommandType.LOGIN, List.of("--username", "user",
                "--password", "pass")), channel);

        String expected = "<You are already logged in>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteLogInExpectedServerStorageFail()
            throws AlreadyLoggedInException,
            StorageFailException,
            InvalidCombinationException,
            InvalidSessionIdException {
        when(defender.isBlocked(any())).thenReturn(false);
        when(userHandler.logIn(any(), any())).thenThrow(StorageFailException.class);

        String actual = commandExecutor.execute(new Command(CommandType.LOGIN, List.of("--username", "user",
                "--password", "pass")), channel);

        String expected = "<A problem in the system has occurred, please try again>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteLogInExpectedSuccess()
            throws AlreadyLoggedInException,
            StorageFailException,
            InvalidCombinationException,
            InvalidSessionIdException {
        when(defender.isBlocked(any())).thenReturn(false);
        String sessionId = "sessionId";
        when(userHandler.logIn(any(), any())).thenReturn(sessionId);

        String actual = commandExecutor.execute(new Command(CommandType.LOGIN, List.of("--username", "user",
                "--password", "pass")), channel);

        String expected = "<You have been successfully logged in, your session id is <" + sessionId + ">>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteLogOutExpectedMissingSentinelOrData() {
        String actual = commandExecutor
                .execute(new Command(CommandType.LOGOUT, List.of("--username", "user")), channel);

        String expected = "<Missing authentication sentinel/data>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteLogOutExpectedInvalidNumberOfArguments() {
        String actual = commandExecutor
                .execute(new Command(CommandType.LOGOUT, List.of("--username", "user", "asd")), channel);

        String expected = "<Wrong number of arguments>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteLogOutExpectedNotLoggedIn()
            throws NotLoggedInException,
            InvalidSessionIdException {
        when(userHandler.logOut(any(), any())).thenThrow(NotLoggedInException.class);

        String actual = commandExecutor
                .execute(new Command(CommandType.LOGOUT, List.of("--session-id", "haha")), channel);

        String expected = "<You are not logged in>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteLogOutExpectedInvalidSession()
            throws NotLoggedInException,
            InvalidSessionIdException {
        when(userHandler.logOut(any(), any())).thenThrow(NotLoggedInException.class);

        String actual = commandExecutor
                .execute(new Command(CommandType.LOGOUT, List.of("--session-id", "haha")), channel);

        String expected = "<You are not logged in>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteLogOutExpectedSuccess()
            throws NotLoggedInException,
            InvalidSessionIdException {
        when(userHandler.logOut(any(), any())).thenReturn(true);

        String actual = commandExecutor
                .execute(new Command(CommandType.LOGOUT, List.of("--session-id", "haha")), channel);

        String expected = "<You logged out successfully>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteUpdateUserExpectedMissingSentinelOrData() {
        String actual = commandExecutor
                .execute(new Command(CommandType.UPDATE_USER, List.of("--username", "user")), channel);

        String expected = "<Missing authentication sentinel/data>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteUpdateUserExpectedInvalidNumberOfArguments() {
        String actual = commandExecutor.execute(new Command(CommandType.UPDATE_USER, List.of("asd")), channel);

        String expected = "<Wrong number of arguments>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteUpdateUserExpectedInvalidSession()
            throws InvalidSessionIdException,
            NoUpdateRequestException,
            NotLoggedInException,
            StorageFailException {
        when(userHandler.updatePersonalInfo(any(), any())).thenThrow(InvalidSessionIdException.class);

        String actual = commandExecutor
                .execute(new Command(CommandType.UPDATE_USER, List.of("--session-id", "ses")), channel);

        String expected = "<Wrong session id>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteUpdateUserExpectedNotLoggedIn()
            throws InvalidSessionIdException,
            NoUpdateRequestException,
            NotLoggedInException,
            StorageFailException {
        when(userHandler.updatePersonalInfo(any(), any())).thenThrow(NotLoggedInException.class);

        String actual = commandExecutor
                .execute(new Command(CommandType.UPDATE_USER, List.of("--session-id", "ses")), channel);

        String expected = "<You are not logged in>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteUpdateUserExpectedServerStorageFail()
            throws InvalidSessionIdException,
            NoUpdateRequestException,
            NotLoggedInException,
            StorageFailException {
        when(userHandler.updatePersonalInfo(any(), any())).thenThrow(StorageFailException.class);

        String actual = commandExecutor
                .execute(new Command(CommandType.UPDATE_USER, List.of("--session-id", "ses")), channel);

        String expected = "<A problem in the system has occurred, please try again>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteUpdateUserExpectedNoUpdateRequested()
            throws InvalidSessionIdException,
            NoUpdateRequestException,
            NotLoggedInException,
            StorageFailException {
        when(userHandler.updatePersonalInfo(any(), any())).thenThrow(NoUpdateRequestException.class);

        String actual = commandExecutor
                .execute(new Command(CommandType.UPDATE_USER, List.of("--session-id", "ses")), channel);

        String expected = "<You did not request any changes>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteUpdateUserExpectedSuccess()
            throws InvalidSessionIdException,
            NoUpdateRequestException,
            NotLoggedInException,
            StorageFailException {
        when(userHandler.updatePersonalInfo(any(), any())).thenReturn(true);

        String actual = commandExecutor
                .execute(new Command(CommandType.UPDATE_USER, List.of("--session-id", "ses")), channel);

        String expected = "<You successfully updated your profile>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteResetPasswordExpectedMissingSentinelOrData() {
        String actual = commandExecutor.execute(new Command(CommandType.RESET_PASSWORD, List.of("--session-id", "user",
                "--username", "user",
                "--old--pasword", "oldpass",
                "newPass", "newPass")), channel);

        String expected = "<Missing authentication sentinel/data>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteResetPasswordExpectedInvalidNumberOfArguments() {
        String actual = commandExecutor
                .execute(new Command(CommandType.RESET_PASSWORD, List.of("--username", "user")), channel);

        String expected = "<Wrong number of arguments>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteResetPasswordExpectedNotLoggedIn()
            throws NotLoggedInException,
            StorageFailException,
            InvalidSessionIdException,
            InvalidCombinationException {
        when(userHandler.updateAccountPassword(any(), any())).thenThrow(NotLoggedInException.class);

        String actual = commandExecutor.execute(new Command(CommandType.RESET_PASSWORD, List.of("--session-id", "ses",
                "--username", "user",
                "--old-password", "oldpass",
                "--new-password", "newPass")), channel);

        String expected = "<You are not logged in>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteResetPasswordExpectedInvalidCombination()
            throws NotLoggedInException,
            StorageFailException,
            InvalidSessionIdException,
            InvalidCombinationException {
        when(userHandler.updateAccountPassword(any(), any())).thenThrow(InvalidCombinationException.class);

        String actual = commandExecutor.execute(new Command(CommandType.RESET_PASSWORD, List.of("--session-id", "ses",
                "--username", "user",
                "--old-password", "oldpass",
                "--new-password", "newPass")), channel);

        String expected = "<Wrong username/password combination>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteResetPasswordExpectedInvalidSessionId()
            throws NotLoggedInException,
            StorageFailException,
            InvalidSessionIdException,
            InvalidCombinationException {
        when(userHandler.updateAccountPassword(any(), any())).thenThrow(InvalidSessionIdException.class);

        String actual = commandExecutor.execute(new Command(CommandType.RESET_PASSWORD, List.of("--session-id", "ses",
                "--username", "user",
                "--old-password", "oldpass",
                "--new-password", "newPass")), channel);

        String expected = "<Wrong session id>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteResetPasswordExpectedServerStorageFail()
            throws NotLoggedInException,
            StorageFailException,
            InvalidSessionIdException,
            InvalidCombinationException {
        when(userHandler.updateAccountPassword(any(), any())).thenThrow(StorageFailException.class);

        String actual = commandExecutor.execute(new Command(CommandType.RESET_PASSWORD, List.of("--session-id", "ses",
                "--username", "user",
                "--old-password", "oldpass",
                "--new-password", "newPass")), channel);

        String expected = "<A problem in the system has occurred, please try again>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteResetPasswordExpectedSuccess()
            throws NotLoggedInException,
            StorageFailException,
            InvalidSessionIdException,
            InvalidCombinationException {
        when(userHandler.updateAccountPassword(any(), any())).thenReturn(true);

        String actual = commandExecutor.execute(new Command(CommandType.RESET_PASSWORD, List.of("--session-id", "ses",
                "--username", "user",
                "--old-password", "oldpass",
                "--new-password", "newPass")), channel);

        String expected = "<You successfully changed your password to <newPass>>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteAddAdminExpectedMissingSentinelOrData() {
        String actual = commandExecutor.execute(new Command(CommandType.ADD_ADMIN_USER, List.of("--session-id", "user",
                "--password", "user")), channel);

        String expected = "<Missing authentication sentinel/data>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteAddAdminExpectedInvalidNumberOfArguments() {
        String actual = commandExecutor
                .execute(new Command(CommandType.ADD_ADMIN_USER, List.of("--username", "user")), channel);

        String expected = "<Wrong number of arguments>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteAddAdminExpectedNotLoggedIn() {
        String actual = commandExecutor.execute(new Command(CommandType.ADD_ADMIN_USER, List.of("--session-id", "ses",
                "--username", "user")), channel);

        String expected = "<You are not logged in>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteAddAdminExpectedInvalidSessionId() {
        when(userHandler.isLoggedIn(any())).thenReturn(true);
        when(userHandler.isSessionValid(any())).thenReturn(false);

        String actual = commandExecutor.execute(new Command(CommandType.ADD_ADMIN_USER, List.of("--session-id", "ses",
                "--username", "user")), channel);

        String expected = "<Wrong session id>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteAddAdminExpectedUserNotFound()
            throws UserNotFoundException,
            NotAuthorizedUserException,
            AlreadyAuthorizedUserException,
            StorageFailException,
            NotLoggedInException,
            InvalidSessionIdException,
            IOException {
        when(userHandler.isLoggedIn(any())).thenReturn(true);
        when(userHandler.isSessionValid(any())).thenReturn(true);
        when(userHandler.makeAdmin(any(), any())).thenThrow(UserNotFoundException.class);
        when(userHandler.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("u", "p"),
                new PersonalInfo("f", "l", "e")));
        when(channel.getRemoteAddress()).thenReturn(socketAddress);
        when(channel.getRemoteAddress().toString()).thenReturn(REMOTE_USER_INFO);

        String actual = commandExecutor.execute(new Command(CommandType.ADD_ADMIN_USER, List.of("--session-id", "ses",
                "--username", "user")), channel);

        String expected = "<User with username <user> does not exist>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteAddAdminExpectedNotAuthorizedUser()
            throws UserNotFoundException,
            NotAuthorizedUserException,
            AlreadyAuthorizedUserException,
            StorageFailException,
            NotLoggedInException,
            InvalidSessionIdException,
            IOException {
        when(userHandler.isLoggedIn(any())).thenReturn(true);
        when(userHandler.isSessionValid(any())).thenReturn(true);
        when(userHandler.makeAdmin(any(), any())).thenThrow(NotAuthorizedUserException.class);
        when(userHandler.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("u", "p"),
                new PersonalInfo("f", "l", "e")));
        when(channel.getRemoteAddress()).thenReturn(socketAddress);
        when(channel.getRemoteAddress().toString()).thenReturn(REMOTE_USER_INFO);

        String actual = commandExecutor.execute(new Command(CommandType.ADD_ADMIN_USER, List.of("--session-id", "ses",
                "--username", "user")), channel);

        String expected = "<Only a admin can add new admin>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteAddAdminExpectedAlreadyAuthorized()
            throws UserNotFoundException,
            NotAuthorizedUserException,
            AlreadyAuthorizedUserException,
            StorageFailException,
            NotLoggedInException,
            InvalidSessionIdException,
            IOException {
        when(userHandler.isLoggedIn(any())).thenReturn(true);
        when(userHandler.isSessionValid(any())).thenReturn(true);
        when(userHandler.makeAdmin(any(), any())).thenThrow(AlreadyAuthorizedUserException.class);
        when(userHandler.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("u", "p"),
                new PersonalInfo("f", "l", "e")));
        when(channel.getRemoteAddress()).thenReturn(socketAddress);
        when(channel.getRemoteAddress().toString()).thenReturn(REMOTE_USER_INFO);

        String actual = commandExecutor.execute(new Command(CommandType.ADD_ADMIN_USER, List.of("--session-id", "ses",
                "--username", "user")), channel);

        String expected = "<User with username <user> is already admin>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteAddAdminExpectedServerStorageFail()
            throws UserNotFoundException,
            NotAuthorizedUserException,
            AlreadyAuthorizedUserException,
            StorageFailException,
            NotLoggedInException,
            InvalidSessionIdException,
            IOException {
        when(userHandler.isLoggedIn(any())).thenReturn(true);
        when(userHandler.isSessionValid(any())).thenReturn(true);
        when(userHandler.makeAdmin(any(), any())).thenThrow(StorageFailException.class);
        when(userHandler.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("u", "p"),
                new PersonalInfo("f", "l", "e")));
        when(channel.getRemoteAddress()).thenReturn(socketAddress);
        when(channel.getRemoteAddress().toString()).thenReturn(REMOTE_USER_INFO);

        String actual = commandExecutor.execute(new Command(CommandType.ADD_ADMIN_USER, List.of("--session-id", "ses",
                "--username", "user")), channel);

        String expected = "<A problem in the system has occurred, please try again>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteAddAdminExpectedSuccess()
            throws UserNotFoundException,
            NotAuthorizedUserException,
            StorageFailException,
            AlreadyAuthorizedUserException,
            InvalidSessionIdException,
            NotLoggedInException,
            IOException {
        when(userHandler.isLoggedIn(any())).thenReturn(true);
        when(userHandler.isSessionValid(any())).thenReturn(true);
        when(userHandler.makeAdmin(any(), any())).thenReturn(true);
        when(userHandler.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("u", "p"),
                new PersonalInfo("f", "l", "e")));
        when(channel.getRemoteAddress()).thenReturn(socketAddress);
        when(channel.getRemoteAddress().toString()).thenReturn(REMOTE_USER_INFO);

        String actual = commandExecutor.execute(new Command(CommandType.ADD_ADMIN_USER, List.of("--session-id", "ses",
                "--username", "user")), channel);

        String expected = "<You successfully added new admin to the system>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteRemoveAdminExpectedMissingSentinelOrData() {
        String actual =
                commandExecutor.execute(new Command(CommandType.REMOVE_ADMIN_USER, List.of("--session-id", "user",
                        "--password", "user")), channel);

        String expected = "<Missing authentication sentinel/data>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteRemoveAdminExpectedInvalidNumberOfArguments() {
        String actual = commandExecutor
                .execute(new Command(CommandType.REMOVE_ADMIN_USER, List.of("--username", "user")), channel);

        String expected = "<Wrong number of arguments>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteRemoveAdminExpectedNotLoggedIn() {
        String actual =
                commandExecutor.execute(new Command(CommandType.REMOVE_ADMIN_USER, List.of("--session-id", "ses",
                        "--username", "user")), channel);

        String expected = "<You are not logged in>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteRemoveAdminExpectedInvalidSessionId() {
        when(userHandler.isLoggedIn(any())).thenReturn(true);
        when(userHandler.isSessionValid(any())).thenReturn(false);

        String actual =
                commandExecutor.execute(new Command(CommandType.REMOVE_ADMIN_USER, List.of("--session-id", "ses",
                        "--username", "user")), channel);

        String expected = "<Wrong session id>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteRemoveAdminExpectedNotAuthorizedUser()
            throws UserNotFoundException,
            NotAuthorizedUserException,
            StorageFailException,
            AlreadyNotAuthorizedUserException,
            NotLoggedInException,
            InvalidSessionIdException,
            IOException {
        when(userHandler.isLoggedIn(any())).thenReturn(true);
        when(userHandler.isSessionValid(any())).thenReturn(true);
        when(userHandler.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("u", "p"),
                new PersonalInfo("f", "l", "e")));
        when(userHandler.removeAdmin(any(), any())).thenThrow(NotAuthorizedUserException.class);
        when(channel.getRemoteAddress()).thenReturn(socketAddress);
        when(channel.getRemoteAddress().toString()).thenReturn(REMOTE_USER_INFO);

        String actual =
                commandExecutor.execute(new Command(CommandType.REMOVE_ADMIN_USER, List.of("--session-id", "ses",
                        "--username", "user")), channel);

        String expected = "<Only a admin can remove admin>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteRemoveAdminExpectedUserNotFound()
            throws UserNotFoundException,
            NotAuthorizedUserException,
            StorageFailException,
            AlreadyNotAuthorizedUserException,
            NotLoggedInException,
            InvalidSessionIdException,
            IOException {
        when(userHandler.isLoggedIn(any())).thenReturn(true);
        when(userHandler.isSessionValid(any())).thenReturn(true);
        when(userHandler.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("u", "p"),
                new PersonalInfo("f", "l", "e")));
        when(userHandler.removeAdmin(any(), any())).thenThrow(UserNotFoundException.class);
        when(channel.getRemoteAddress()).thenReturn(socketAddress);
        when(channel.getRemoteAddress().toString()).thenReturn(REMOTE_USER_INFO);

        String actual =
                commandExecutor.execute(new Command(CommandType.REMOVE_ADMIN_USER, List.of("--session-id", "ses",
                        "--username", "user")), channel);

        String expected = "<User with username <user> does not exist>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteRemoveAdminExpectedServerStorageFail()
            throws UserNotFoundException,
            NotAuthorizedUserException,
            StorageFailException,
            AlreadyNotAuthorizedUserException,
            NotLoggedInException,
            InvalidSessionIdException,
            IOException {
        when(userHandler.isLoggedIn(any())).thenReturn(true);
        when(userHandler.isSessionValid(any())).thenReturn(true);
        when(userHandler.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("u", "p"),
                new PersonalInfo("f", "l", "e")));
        when(userHandler.removeAdmin(any(), any())).thenThrow(StorageFailException.class);
        when(channel.getRemoteAddress()).thenReturn(socketAddress);
        when(channel.getRemoteAddress().toString()).thenReturn(REMOTE_USER_INFO);

        String actual =
                commandExecutor.execute(new Command(CommandType.REMOVE_ADMIN_USER, List.of("--session-id", "ses",
                        "--username", "user")), channel);

        String expected = "<A problem in the system has occurred, please try again>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteRemoveAdminExpectedAlreadyNotAuthorizedUser()
            throws UserNotFoundException,
            NotAuthorizedUserException,
            StorageFailException,
            AlreadyNotAuthorizedUserException,
            NotLoggedInException,
            InvalidSessionIdException,
            IOException {
        when(userHandler.isLoggedIn(any())).thenReturn(true);
        when(userHandler.isSessionValid(any())).thenReturn(true);
        when(userHandler.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("u", "p"),
                new PersonalInfo("f", "l", "e")));
        when(userHandler.removeAdmin(any(), any())).thenThrow(AlreadyNotAuthorizedUserException.class);
        when(channel.getRemoteAddress()).thenReturn(socketAddress);
        when(channel.getRemoteAddress().toString()).thenReturn(REMOTE_USER_INFO);

        String actual =
                commandExecutor.execute(new Command(CommandType.REMOVE_ADMIN_USER, List.of("--session-id", "ses",
                        "--username", "user")), channel);

        String expected = "<User with username <user> is not admin>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteRemoveAdminExpectedSuccess()
            throws UserNotFoundException,
            NotAuthorizedUserException,
            StorageFailException,
            AlreadyNotAuthorizedUserException,
            NotLoggedInException,
            InvalidSessionIdException,
            IOException {
        when(userHandler.isLoggedIn(any())).thenReturn(true);
        when(userHandler.isSessionValid(any())).thenReturn(true);
        when(userHandler.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("u", "p"),
                new PersonalInfo("f", "l", "e")));
        when(userHandler.removeAdmin(any(), any())).thenReturn(true);
        when(channel.getRemoteAddress()).thenReturn(socketAddress);
        when(channel.getRemoteAddress().toString()).thenReturn(REMOTE_USER_INFO);

        String actual =
                commandExecutor.execute(new Command(CommandType.REMOVE_ADMIN_USER, List.of("--session-id", "ses",
                        "--username", "user")), channel);

        String expected = "<You removed a admin successfully>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteDeleteUserExpectedMissingSentinelOrData() {
        String actual = commandExecutor.execute(new Command(CommandType.DELETE_USER, List.of("--session-id", "user",
                "--password", "user")), channel);

        String expected = "<Missing authentication sentinel/data>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteDeleteUserExpectedInvalidNumberOfArguments() {
        String actual = commandExecutor
                .execute(new Command(CommandType.DELETE_USER, List.of("--username", "user")), channel);

        String expected = "<Wrong number of arguments>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteDeleteUserExpectedNotLoggedIn() {
        String actual = commandExecutor.execute(new Command(CommandType.DELETE_USER, List.of("--session-id", "user",
                "--username", "user")), channel);

        String expected = "<You are not logged in>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteDeleteUserExpectedNotAuthorized()
            throws UserNotFoundException,
            InvalidSessionIdException,
            NotAuthorizedUserException,
            NotLoggedInException,
            StorageFailException {
        when(userHandler.removeUser(any(), any())).thenThrow(NotAuthorizedUserException.class);
        when(userHandler.isLoggedIn(any())).thenReturn(true);
        when(userHandler.isSessionValid(any())).thenReturn(true);

        String actual = commandExecutor.execute(new Command(CommandType.DELETE_USER, List.of("--session-id", "user",
                "--username", "user")), channel);

        String expected = "<Only a admin can remove user>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteDeleteUserExpectedUserNotFound()
            throws UserNotFoundException,
            InvalidSessionIdException,
            NotAuthorizedUserException,
            NotLoggedInException,
            StorageFailException {
        when(userHandler.removeUser(any(), any())).thenThrow(UserNotFoundException.class);
        when(userHandler.isLoggedIn(any())).thenReturn(true);
        when(userHandler.isSessionValid(any())).thenReturn(true);

        String actual = commandExecutor.execute(new Command(CommandType.DELETE_USER, List.of("--session-id", "user",
                "--username", "user")), channel);

        String expected = "<User with username <user> does not exist>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteDeleteUserExpectedServerStorageFail()
            throws UserNotFoundException,
            InvalidSessionIdException,
            NotAuthorizedUserException,
            NotLoggedInException,
            StorageFailException {
        when(userHandler.removeUser(any(), any())).thenThrow(StorageFailException.class);
        when(userHandler.isLoggedIn(any())).thenReturn(true);
        when(userHandler.isSessionValid(any())).thenReturn(true);

        String actual = commandExecutor.execute(new Command(CommandType.DELETE_USER, List.of("--session-id", "user",
                "--username", "user")), channel);

        String expected = "<A problem in the system has occurred, please try again>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteDeleteUserExpectedSuccess()
            throws UserNotFoundException,
            InvalidSessionIdException,
            NotAuthorizedUserException,
            NotLoggedInException,
            StorageFailException {
        when(userHandler.removeUser(any(), any())).thenReturn(true);
        when(userHandler.isLoggedIn(any())).thenReturn(true);
        when(userHandler.isSessionValid(any())).thenReturn(true);

        String actual = commandExecutor.execute(new Command(CommandType.DELETE_USER, List.of("--session-id", "user",
                "--username", "user")), channel);

        String expected = "<You deleted a user successfully>";

        assertEquals("expecting exact same response", expected, actual);
    }

    @Test
    public void testExecuteInvalidCommand() {
        String actual = commandExecutor.execute(new Command(CommandType.INVALID, null), channel);
        String expected = "<Unknown command>";

        assertEquals("expecting exact same response", expected, actual);
    }
}
