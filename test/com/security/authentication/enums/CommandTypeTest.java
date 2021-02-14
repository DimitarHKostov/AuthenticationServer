package com.security.authentication.enums;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class CommandTypeTest {
    @Test(expected = IllegalArgumentException.class)
    public void testGetTypeExpectedIllegalArgumentException() {
        CommandType.getType(null);
    }

    @Test
    public void getTypeExpectedRegister() {
        CommandType actual = CommandType.getType("register");
        CommandType expected = CommandType.REGISTER;

        assertEquals("expecting register command", expected, actual);
    }

    @Test
    public void getTypeExpectedLogin() {
        CommandType actual = CommandType.getType("login");
        CommandType expected = CommandType.LOGIN;

        assertEquals("expecting login command", expected, actual);
    }

    @Test
    public void getTypeExpectedUpdateUser() {
        CommandType actual = CommandType.getType("update-user");
        CommandType expected = CommandType.UPDATE_USER;

        assertEquals("expecting update user command", expected, actual);
    }

    @Test
    public void getTypeExpectedResetPassword() {
        CommandType actual = CommandType.getType("reset-password");
        CommandType expected = CommandType.RESET_PASSWORD;

        assertEquals("expecting reset password command", expected, actual);
    }

    @Test
    public void getTypeExpectedLogOut() {
        CommandType actual = CommandType.getType("logout");
        CommandType expected = CommandType.LOGOUT;

        assertEquals("expecting logout command", expected, actual);
    }

    @Test
    public void getTypeExpectedAddAdminUser() {
        CommandType actual = CommandType.getType("add-admin-user");
        CommandType expected = CommandType.ADD_ADMIN_USER;

        assertEquals("expecting add admin user command", expected, actual);
    }

    @Test
    public void getTypeExpectedRemoveAdminUser() {
        CommandType actual = CommandType.getType("remove-admin-user");
        CommandType expected = CommandType.REMOVE_ADMIN_USER;

        assertEquals("expecting remove admin user command", expected, actual);
    }

    @Test
    public void getTypeExpectedDeleteUser() {
        CommandType actual = CommandType.getType("delete-user");
        CommandType expected = CommandType.DELETE_USER;

        assertEquals("expecting delete user command", expected, actual);
    }

    @Test
    public void getTypeExpectedInvalid() {
        CommandType actual = CommandType.getType("random");
        CommandType expected = CommandType.INVALID;

        assertEquals("expecting invalid command", expected, actual);
    }
}
