package com.security.authentication.storage;

import com.security.authentication.enums.ChangeRequest;
import com.security.authentication.exceptions.storage.RemoveFailException;
import com.security.authentication.exceptions.storage.StorageFailException;
import com.security.authentication.exceptions.storage.UserNotFoundException;
import com.security.authentication.exceptions.update.NoUpdateRequestException;
import com.security.authentication.exceptions.update.UpdateFailException;
import com.security.authentication.generator.Generator;
import com.security.authentication.generator.SecretKeyGenerator;
import com.security.authentication.user.RegularUser;
import com.security.authentication.user.UnauthenticatedUser;
import com.security.authentication.user.User;
import com.security.authentication.user.info.AccountInfo;
import com.security.authentication.user.info.PersonalInfo;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class FileSystemStorageTest {
    private static Storage storage;

    @BeforeClass
    public static void setUp() throws IOException {
        Generator<SecretKey> secretKeyGenerator = new SecretKeyGenerator();
        SecretKey secretKey = secretKeyGenerator.generate();
        File file = File.createTempFile("frontHaha", "endHaha");
        storage = new FileSystemStorage(Path.of(file.toString()), secretKey);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testAddExpectedIllegalArgumentException() throws StorageFailException {
        storage.add(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRemoveExpectedIllegalArgumentException() throws RemoveFailException {
        storage.remove(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testUpdateExpectedIllegalArgumentExceptionWhenUserNull()
            throws NoUpdateRequestException, UpdateFailException {
        storage.update(null, Map.of(ChangeRequest.NEW_PASSWORD, "asd"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testUpdateExpectedIllegalArgumentExceptionWhenRequestsNull()
            throws NoUpdateRequestException, UpdateFailException {
        storage.update(new UnauthenticatedUser(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email")), null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testHasStoredInfoExpectedIllegalArgumentException() throws StorageFailException {
        storage.hasStoredInfo(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testExtractExpectedIllegalArgumentExceptionWhenRequestsNull()
            throws StorageFailException, UserNotFoundException {
        storage.extract(null);
    }

    @Test
    public void testAddExpectedSuccess() throws StorageFailException {
        boolean actual = storage.add(new UnauthenticatedUser(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email")));

        assertTrue("should be added new user", actual);
    }

    @Test
    public void testHasStoredInfoExpectedTrue()
            throws StorageFailException {
        User user = new UnauthenticatedUser(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email"));

        storage.add(user);

        boolean actual = storage.hasStoredInfo(user);

        assertTrue("should have stored data", actual);
    }

    @Test
    public void testHasStoredInfoExpectedFalse()
            throws StorageFailException {
        User user = new UnauthenticatedUser(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email"));

        User user2 = new UnauthenticatedUser(new AccountInfo("user2", "password"),
                new PersonalInfo("fname", "lname", "email"));

        storage.add(user);

        boolean actual = storage.hasStoredInfo(user2);

        assertFalse("should not have stored data", actual);
    }

    @Test
    public void testExtractExpectedSuccess()
            throws StorageFailException,
            UserNotFoundException {
        User user = new RegularUser(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email"));

        storage.add(user);

        User actual = storage.extract(user.getAccountInfo().getUsername());

        assertEquals("should be same", user, actual);
    }

    @Test(expected = UserNotFoundException.class)
    public void testExtractExpectedUserNotFoundException()
            throws StorageFailException,
            UserNotFoundException {
        User user = new UnauthenticatedUser(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email"));

        storage.extract(user.getAccountInfo().getUsername());
    }

    @Test(expected = NoUpdateRequestException.class)
    public void testUpdateExpectedNoUpdateRequestException()
            throws NoUpdateRequestException, UpdateFailException {
        User user = new UnauthenticatedUser(new AccountInfo("user", "password"),
                new PersonalInfo("fname", "lname", "email"));

        storage.update(user, Map.of());
    }
}
