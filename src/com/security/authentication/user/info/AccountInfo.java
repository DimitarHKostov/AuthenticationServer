package com.security.authentication.user.info;

public class AccountInfo {
    private final String username;
    private final String password;

    public AccountInfo(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return this.username;
    }

    public String getPassword() {
        return this.password;
    }

    @Override
    public boolean equals(Object other) {
        if (other == null) {
            return false;
        }

        if (getClass() != other.getClass()) {
            return false;
        }

        AccountInfo otherAccountInfo = (AccountInfo) other;

        return username.equals(otherAccountInfo.getUsername()) && password.equals(otherAccountInfo.getPassword());
    }
}
