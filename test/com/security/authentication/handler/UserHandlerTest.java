package com.security.authentication.handler;

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
import com.security.authentication.exceptions.update.UpdateFailException;
import com.security.authentication.storage.Storage;
import com.security.authentication.user.Admin;
import com.security.authentication.user.UnauthenticatedUser;
import com.security.authentication.user.User;
import com.security.authentication.user.info.AccountInfo;
import com.security.authentication.user.info.PersonalInfo;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.nio.channels.SocketChannel;
import java.util.List;

import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class UserHandlerTest {
    private static final String IP = "196.124.0.5";

    @Mock
    private Storage storage;

    @InjectMocks
    private UserHandler userHandler;

    @Mock
    private SocketChannel channel;

    @Test(expected = IllegalArgumentException.class)
    public void testRegisterExpectedIllegalArgumentExceptionWhenParametersNull()
            throws UserAlreadyRegisteredException,
            AlreadyLoggedInException,
            EmptyStorageException,
            StorageFailException {
        userHandler.register(null, channel);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRegisterExpectedIllegalArgumentExceptionWhenChannelNull()
            throws UserAlreadyRegisteredException,
            AlreadyLoggedInException,
            EmptyStorageException,
            StorageFailException {
        userHandler.register(List.of("random"), null);
    }

    @Test(expected = EmptyStorageException.class)
    public void testRegisterExpectedEmptyStorageException()
            throws UserAlreadyRegisteredException,
            AlreadyLoggedInException,
            EmptyStorageException,
            StorageFailException {

        when(storage.isEmpty()).thenReturn(true);
        when(storage.hasStoredInfo(any())).thenReturn(false);
        when(storage.add(any(User.class))).thenReturn(true);

        userHandler.register(List.of("--username", "user",
                "--password", "password",
                "--first-name", "fname",
                "--last-name", "lname",
                "--email", "email"), channel);
    }

    @Test(expected = UserAlreadyRegisteredException.class)
    public void testRegisterExpectedUserAlreadyRegisteredException()
            throws UserAlreadyRegisteredException,
            AlreadyLoggedInException,
            EmptyStorageException,
            StorageFailException {

        when(storage.hasStoredInfo(any())).thenReturn(true);

        userHandler.register(List.of("--username", "user",
                "--password", "password",
                "--first-name", "fname",
                "--last-name", "lname",
                "--email", "email"), channel);
    }

    @Test(expected = AlreadyLoggedInException.class)
    public void testRegisterExpectedAlreadyLoggedInException()
            throws UserAlreadyRegisteredException,
            AlreadyLoggedInException,
            EmptyStorageException,
            StorageFailException,
            UserNotFoundException,
            InvalidCombinationException,
            InvalidSessionIdException {

        when(storage.isEmpty()).thenReturn(false);
        when(storage.hasStoredInfo(any())).thenReturn(false);
        when(storage.add(any())).thenReturn(true);

        userHandler.register(List.of("--username", "user",
                "--password", "password",
                "--first-name", "fname",
                "--last-name", "lname",
                "--email", "email"), channel);

        when(storage.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email")));

        userHandler.logIn(List.of("--username", "user", "password", "password"), channel);

        userHandler.register(List.of("--username", "user2",
                "--password", "password",
                "--first-name", "fname",
                "--last-name", "lname",
                "--email", "email"), channel);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testLogInExpectedIllegalArgumentExceptionWhenParametersNull()
            throws AlreadyLoggedInException,
            StorageFailException,
            InvalidCombinationException,
            InvalidSessionIdException {
        userHandler.logIn(null, channel);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testLogInExpectedIllegalArgumentExceptionWhenChannelNull()
            throws AlreadyLoggedInException,
            StorageFailException,
            InvalidCombinationException,
            InvalidSessionIdException {
        userHandler.logIn(List.of("random"), null);
    }

    @Test(expected = InvalidCombinationException.class)
    public void testLogInExpectedInvalidCombinationExceptionWhenUserNotFoundException()
            throws AlreadyLoggedInException,
            StorageFailException,
            InvalidCombinationException,
            InvalidSessionIdException,
            UserNotFoundException {

        when(storage.extract(any())).thenThrow(UserNotFoundException.class);

        userHandler.logIn(List.of("--username", "user", "--password", "pass"), channel);
    }

    @Test(expected = InvalidCombinationException.class)
    public void testLogInExpectedInvalidCombinationExceptionWhenPasswordsDoNotMatch()
            throws AlreadyLoggedInException,
            StorageFailException,
            InvalidCombinationException,
            InvalidSessionIdException,
            UserNotFoundException {

        when(storage.extract(any())).thenReturn(new Admin(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email")));

        userHandler.logIn(List.of("--username", "user", "--password", "pasdass"), channel);
    }

    @Test(expected = AlreadyLoggedInException.class)
    public void testLogInExpectedAlreadyLoggedInException()
            throws AlreadyLoggedInException,
            StorageFailException,
            InvalidCombinationException,
            InvalidSessionIdException,
            UserNotFoundException {

        when(storage.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email")));

        userHandler.logIn(List.of("--username", "user", "--password", "password"), channel);

        userHandler.logIn(List.of("--username", "user", "--password", "password"), channel);
    }

    @Test(expected = InvalidSessionIdException.class)
    public void testLogInInvalidSessionIdException()
            throws AlreadyLoggedInException,
            StorageFailException,
            InvalidCombinationException,
            InvalidSessionIdException,
            UserNotFoundException,
            NotLoggedInException {

        when(storage.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email")));

        String sessionId = userHandler.logIn(List.of("--username", "user", "--password", "password"), channel);

        userHandler.logOut(List.of("--session-id", sessionId), channel);

        userHandler.logIn(List.of("--session-id", "asd"), channel);
    }

    @Test(expected = AlreadyLoggedInException.class)
    public void testLogInAlreadyLoggedInExceptionSession()
            throws AlreadyLoggedInException,
            StorageFailException,
            InvalidCombinationException,
            InvalidSessionIdException,
            UserNotFoundException {

        when(storage.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email")));

        userHandler.logIn(List.of("--username", "user", "--password", "password"), channel);

        userHandler.logIn(List.of("--session-id", "asd"), channel);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testLogOutExpectedIllegalArgumentExceptionWhenParametersNull()
            throws InvalidSessionIdException,
            NotLoggedInException {
        userHandler.logOut(null, channel);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testLogOutExpectedIllegalArgumentExceptionWhenChannelNull()
            throws InvalidSessionIdException,
            NotLoggedInException {
        userHandler.logOut(List.of("random"), null);
    }

    @Test(expected = InvalidSessionIdException.class)
    public void testLogOutExpectedInvalidSessionIdException()
            throws AlreadyLoggedInException,
            StorageFailException,
            InvalidCombinationException,
            InvalidSessionIdException,
            UserNotFoundException,
            NotLoggedInException {

        when(storage.extract(any())).thenReturn(new User(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email")) {
        });

        userHandler.logIn(List.of("--username", "user", "--password", "password"), channel);

        userHandler.logOut(List.of("--session-id", "random"), channel);
    }

    @Test(expected = NotLoggedInException.class)
    public void testLogOutExpectedNotLoggedInException()
            throws InvalidSessionIdException,
            NotLoggedInException {

        userHandler.logOut(List.of("--session-id", "random"), channel);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testUpdateAccountPasswordExpectedIllegalArgumentExceptionWhenParametersNull()
            throws InvalidSessionIdException,
            NotLoggedInException,
            StorageFailException,
            InvalidCombinationException {
        userHandler.updateAccountPassword(null, channel);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testUpdateAccountPasswordExpectedIllegalArgumentExceptionWhenIpNull()
            throws InvalidSessionIdException,
            NotLoggedInException,
            StorageFailException,
            InvalidCombinationException {
        userHandler.updateAccountPassword(List.of("random"), null);
    }

    @Test(expected = NotLoggedInException.class)
    public void testUpdateAccountPasswordExpectedNotLoggedInException()
            throws InvalidSessionIdException,
            NotLoggedInException,
            StorageFailException,
            InvalidCombinationException {

        userHandler.updateAccountPassword(List.of("--session-id", "sessionId",
                "--username", "username",
                "--old-password", "oldPass",
                "--new-password", "newPass"), channel);
    }

    @Test(expected = InvalidSessionIdException.class)
    public void testUpdateAccountPasswordExpectedInvalidSessionIdException()
            throws InvalidSessionIdException,
            NotLoggedInException,
            StorageFailException,
            InvalidCombinationException,
            UserNotFoundException,
            AlreadyLoggedInException {

        when(storage.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email")));

        userHandler.logIn(List.of("--username", "user", "--password", "password"), channel);

        userHandler.updateAccountPassword(List.of("--session-id", "a",
                "--username", "username",
                "--old-password", "oldPass",
                "--new-password", "newPass"), channel);
    }

    @Test(expected = InvalidCombinationException.class)
    public void testUpdateAccountPasswordExpectedInvalidCombinationExceptionWrongUsername()
            throws InvalidSessionIdException,
            NotLoggedInException,
            StorageFailException,
            InvalidCombinationException,
            UserNotFoundException,
            AlreadyLoggedInException {

        when(storage.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email")));

        String sessionId = userHandler.logIn(List.of("--username", "user", "--password", "password"), channel);

        userHandler.updateAccountPassword(List.of("--session-id", sessionId,
                "--username", "username1",
                "--old-password", "password",
                "--new-password", "newPass"), channel);
    }

    @Test(expected = InvalidCombinationException.class)
    public void testUpdateAccountPasswordExpectedInvalidCombinationExceptionWrongPassword()
            throws InvalidSessionIdException,
            NotLoggedInException,
            StorageFailException,
            InvalidCombinationException,
            UserNotFoundException,
            AlreadyLoggedInException {

        when(storage.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email")));

        String sessionId = userHandler.logIn(List.of("--username", "user", "--password", "password"), channel);

        userHandler.updateAccountPassword(List.of("--session-id", sessionId,
                "--username", "username",
                "--old-password", "oldPass",
                "--new-password", "newPass"), channel);
    }

    @Test(expected = StorageFailException.class)
    public void testUpdateAccountPasswordExpectedStorageFailExceptionWhenUpdateFailException()
            throws InvalidSessionIdException,
            NotLoggedInException,
            StorageFailException,
            InvalidCombinationException,
            UserNotFoundException,
            AlreadyLoggedInException,
            NoUpdateRequestException,
            UpdateFailException {

        when(storage.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email")));

        String sessionId = userHandler.logIn(List.of("--username", "user", "--password", "password"), channel);

        when(storage.update(any(), any())).thenThrow(UpdateFailException.class);

        userHandler.updateAccountPassword(List.of("--session-id", sessionId,
                "--username", "user",
                "--old-password", "password",
                "--new-password", "newPass"), channel);
    }

    @Test(expected = StorageFailException.class)
    public void testUpdateAccountPasswordExpectedStorageFailExceptionWhenNoUpdateRequestException()
            throws InvalidSessionIdException,
            NotLoggedInException,
            StorageFailException,
            InvalidCombinationException,
            UserNotFoundException,
            AlreadyLoggedInException,
            NoUpdateRequestException,
            UpdateFailException {

        when(storage.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email")));

        String sessionId = userHandler.logIn(List.of("--username", "user", "--password", "password"), channel);

        when(storage.update(any(), any())).thenThrow(NoUpdateRequestException.class);

        userHandler.updateAccountPassword(List.of("--session-id", sessionId,
                "--username", "user",
                "--old-password", "password",
                "--new-password", "newPass"), channel);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testUpdatePersonalInfoExpectedIllegalArgumentExceptionWhenParametersNull()
            throws InvalidSessionIdException,
            NotLoggedInException,
            StorageFailException,
            InvalidCombinationException {
        userHandler.updateAccountPassword(null, channel);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testUpdatePersonalInfoExpectedIllegalArgumentExceptionWhenChannelNull()
            throws InvalidSessionIdException,
            NotLoggedInException,
            StorageFailException,
            InvalidCombinationException {
        userHandler.updateAccountPassword(List.of("random"), null);
    }

    @Test(expected = NotLoggedInException.class)
    public void testUpdatePersonalInfoExpectedNotLoggedInException()
            throws InvalidSessionIdException,
            NotLoggedInException,
            StorageFailException,
            NoUpdateRequestException {

        userHandler.updatePersonalInfo(List.of("--session-id", "sessionId", "--new-username", "username"), channel);
    }

    @Test(expected = InvalidSessionIdException.class)
    public void testUpdatePersonalInfoExpectedInvalidSessionIdException()
            throws InvalidSessionIdException,
            NotLoggedInException,
            StorageFailException,
            InvalidCombinationException,
            UserNotFoundException,
            AlreadyLoggedInException,
            NoUpdateRequestException {

        when(storage.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email")));

        userHandler.logIn(List.of("--username", "user", "--password", "password"), channel);

        userHandler.updatePersonalInfo(List.of("--session-id", "sessionId", "--new-username", "username"), channel);
    }

    @Test(expected = StorageFailException.class)
    public void testUpdatePersonalInfoExpectedStorageFailExceptionWhenUpdateFailException()
            throws InvalidSessionIdException,
            NotLoggedInException,
            StorageFailException,
            InvalidCombinationException,
            UserNotFoundException,
            AlreadyLoggedInException,
            NoUpdateRequestException,
            UpdateFailException {

        when(storage.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email")));

        String sessionId = userHandler.logIn(List.of("--username", "user", "--password", "password"), channel);

        when(storage.update(any(), any())).thenThrow(UpdateFailException.class);

        userHandler.updatePersonalInfo(List.of("--session-id", sessionId, "--new-username", "username"), channel);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testMakeAdminExpectedIllegalArgumentExceptionWhenParametersNull()
            throws StorageFailException,
            UserNotFoundException,
            AlreadyAuthorizedUserException,
            NotAuthorizedUserException,
            NotLoggedInException,
            InvalidSessionIdException {
        userHandler.makeAdmin(null, channel);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testMakeAdminExpectedIllegalArgumentExceptionWhenChannelNull()
            throws StorageFailException,
            UserNotFoundException,
            AlreadyAuthorizedUserException,
            NotAuthorizedUserException,
            NotLoggedInException,
            InvalidSessionIdException {
        userHandler.makeAdmin(List.of("random"), null);
    }

    @Test(expected = NotAuthorizedUserException.class)
    public void testMakeAdminExpectedNotAuthorizedUserExceptionWhenRegularUserTriesToMakeAdmin()
            throws StorageFailException,
            UserNotFoundException,
            AlreadyAuthorizedUserException,
            NotAuthorizedUserException,
            InvalidCombinationException,
            AlreadyLoggedInException,
            InvalidSessionIdException,
            NotLoggedInException {
        when(storage.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email")));

        String sessionId = userHandler.logIn(List.of("--username", "user", "--password", "password"), channel);

        userHandler.makeAdmin(List.of("--session-id", sessionId, "--username", "user23"), channel);
    }

    @Test(expected = AlreadyAuthorizedUserException.class)
    public void testMakeAdminExpectedAlreadyAuthorizedUserExceptionWhenUserIsAlreadyAdmin()
            throws StorageFailException,
            UserNotFoundException,
            AlreadyAuthorizedUserException,
            NotAuthorizedUserException,
            InvalidCombinationException,
            AlreadyLoggedInException,
            InvalidSessionIdException,
            NotLoggedInException {
        when(storage.extract(any())).thenReturn(new Admin(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email")));

        String sessionId = userHandler.logIn(List.of("--username", "user", "--password", "password"), channel);

        userHandler.makeAdmin(List.of("--session-id", sessionId, "--username", "user23"), channel);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRemoveAdminExpectedIllegalArgumentExceptionWhenParametersNull()
            throws StorageFailException,
            UserNotFoundException,
            NotAuthorizedUserException,
            AlreadyNotAuthorizedUserException,
            NotLoggedInException,
            InvalidSessionIdException {
        userHandler.removeAdmin(null, channel);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRemoveAdminExpectedIllegalArgumentExceptionWhenChannelNull()
            throws StorageFailException,
            UserNotFoundException,
            NotAuthorizedUserException,
            AlreadyNotAuthorizedUserException,
            NotLoggedInException,
            InvalidSessionIdException {
        userHandler.removeAdmin(List.of("random"), null);
    }

    @Test(expected = NotAuthorizedUserException.class)
    public void testRemoveAdminExpectedNotAuthorizedUserExceptionWhenRegularUserTriesToRemoveAdmin()
            throws StorageFailException,
            UserNotFoundException,
            NotAuthorizedUserException,
            InvalidCombinationException,
            AlreadyLoggedInException,
            InvalidSessionIdException,
            AlreadyNotAuthorizedUserException,
            NotLoggedInException {
        when(storage.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email")));

        String sessionId = userHandler.logIn(List.of("--username", "user", "--password", "password"), channel);

        userHandler.removeAdmin(List.of("--session-id", sessionId, "--username", "user23"), channel);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRemoveUserExpectedIllegalArgumentExceptionWhenParametersNull()
            throws StorageFailException,
            UserNotFoundException,
            NotAuthorizedUserException,
            NotLoggedInException,
            InvalidSessionIdException {
        userHandler.removeUser(null, channel);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRemoveUserExpectedIllegalArgumentExceptionWhenChannelNull()
            throws StorageFailException,
            UserNotFoundException,
            NotAuthorizedUserException,
            NotLoggedInException,
            InvalidSessionIdException {
        userHandler.removeUser(List.of("random"), null);
    }

    @Test(expected = NotLoggedInException.class)
    public void testRemoveUserExpectedNotLoggedInException()
            throws InvalidSessionIdException,
            NotLoggedInException,
            StorageFailException,
            UserNotFoundException,
            NotAuthorizedUserException {

        userHandler.removeUser(List.of("--session-id", "sessionId", "--username", "username"), channel);
    }

    @Test(expected = InvalidSessionIdException.class)
    public void testRemoveUserExpectedInvalidSessionIdException()
            throws InvalidSessionIdException,
            NotLoggedInException,
            StorageFailException,
            InvalidCombinationException,
            UserNotFoundException,
            AlreadyLoggedInException,
            NotAuthorizedUserException {

        when(storage.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email")));

        userHandler.logIn(List.of("--username", "user", "--password", "password"), channel);

        userHandler.removeUser(List.of("--session-id", "a", "--username", "username"), channel);
    }

    @Test(expected = NotAuthorizedUserException.class)
    public void testRemoveUserExpectedNotAuthorizedUserExceptionWhenRegularUserTriesToRemoveAdmin()
            throws StorageFailException,
            UserNotFoundException,
            NotAuthorizedUserException,
            InvalidCombinationException,
            AlreadyLoggedInException,
            InvalidSessionIdException,
            NotLoggedInException {
        when(storage.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email")));

        String sessionId = userHandler.logIn(List.of("--username", "user", "--password", "password"), channel);

        userHandler.removeUser(List.of("--session-id", sessionId, "--username", "user23"), channel);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testExtractExpectedIllegalArgumentException() {
        userHandler.extract(null);
    }

    @Test
    public void testRegisterExpectedSuccess()
            throws StorageFailException,
            UserAlreadyRegisteredException,
            EmptyStorageException,
            AlreadyLoggedInException {
        when(storage.isEmpty()).thenReturn(false);
        when(storage.hasStoredInfo(any())).thenReturn(false);
        when(storage.add(any())).thenReturn(true);

        assertTrue("expecting successful register", userHandler.register(List.of("--username", "user",
                "--password", "password",
                "--first-name", "fname",
                "--last-name", "lname",
                "--email", "email"), channel));
    }

    @Test
    public void testLogOutExpectedSuccess()
            throws StorageFailException,
            UserNotFoundException,
            InvalidCombinationException,
            AlreadyLoggedInException,
            InvalidSessionIdException,
            NotLoggedInException {
        when(storage.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email")));

        String sessionId = userHandler.logIn(List.of("--username", "user", "--password", "password"), channel);

        assertTrue("expected successful log out", userHandler.logOut(List.of("--session-id", sessionId), channel));
    }

    @Test
    public void testUpdateAccountPasswordSuccess()
            throws StorageFailException,
            UserNotFoundException,
            InvalidCombinationException,
            AlreadyLoggedInException,
            InvalidSessionIdException,
            NotLoggedInException {
        when(storage.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email")));

        String sessionId = userHandler.logIn(List.of("--username", "user", "--password", "password"), channel);

        assertTrue("expected successful password reset",
                userHandler.updateAccountPassword(List.of("--session-id", sessionId,
                        "--username", "user",
                        "--old-password", "password",
                        "--new-password", "newPass"), channel));
    }

    @Test
    public void testUpdatePersonalInfoSuccess()
            throws NoUpdateRequestException,
            UpdateFailException,
            StorageFailException,
            UserNotFoundException,
            InvalidCombinationException,
            AlreadyLoggedInException,
            InvalidSessionIdException,
            NotLoggedInException {
        when(storage.extract(any())).thenReturn(new UnauthenticatedUser(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email")));

        String sessionId = userHandler.logIn(List.of("--username", "user", "--password", "password"), channel);

        when(storage.update(any(), any())).thenReturn(true);

        assertTrue("expecting successful personal info update",
                userHandler
                        .updatePersonalInfo(List.of("--session-id", sessionId, "--new-username", "username"), channel));

    }
}
