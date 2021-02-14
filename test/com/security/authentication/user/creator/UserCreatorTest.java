package com.security.authentication.user.creator;

import com.security.authentication.user.Admin;
import com.security.authentication.user.UnauthenticatedUser;
import com.security.authentication.user.User;
import com.security.authentication.user.info.AccountInfo;
import com.security.authentication.user.info.PersonalInfo;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;

public class UserCreatorTest {
    private static final List<String> parameters =
            List.of("--username", "user",
                    "--password", "password",
                    "--first-name", "john",
                    "--last-name", "smith",
                    "--email", "email@email");

    @Test(expected = IllegalArgumentException.class)
    public void testCreateParametersExpectedIllegalArgumentException() {
        UserCreator.create(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testCreateArgumentsExpectedIllegalArgumentException() {
        UserCreator.create(null, null);
    }

    @Test
    public void testCreateParametersExpectedRegularUser() {
        User actual = UserCreator.create(parameters);
        User expected = new UnauthenticatedUser(new AccountInfo("user", "password"),
                new PersonalInfo("john", "smith", "email@email"));

        assertEquals("expecting user with same data", expected, actual);
    }

    @Test
    public void testCreateArgumentsExpectedRegularUser() {
        AccountInfo accountInfo = new AccountInfo("user", "password");
        PersonalInfo personalInfo = new PersonalInfo("john", "smith", "email@email");

        User actual = UserCreator.create(accountInfo, personalInfo);

        User expected = new UnauthenticatedUser(accountInfo, personalInfo);

        assertEquals("expecting admin with same data", expected, actual);
    }
}
