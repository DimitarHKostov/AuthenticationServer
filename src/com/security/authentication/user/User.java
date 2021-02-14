package com.security.authentication.user;

import com.security.authentication.user.info.AccountInfo;
import com.security.authentication.user.info.PersonalInfo;

public class User {
    protected PersonalInfo personalInfo;
    protected AccountInfo accountInfo;
    protected boolean isAuthorized;

    public User(AccountInfo accountInfo, PersonalInfo personalInfo) {
        this.accountInfo = accountInfo;
        this.personalInfo = personalInfo;
    }

    public PersonalInfo getPersonalInfo() {
        return personalInfo;
    }

    public AccountInfo getAccountInfo() {
        return accountInfo;
    }

    public boolean isAuthorized() {
        return isAuthorized;
    }

    @Override
    public boolean equals(Object other) {
        if (other == null) {
            return false;
        }

        if (getClass() != other.getClass()) {
            return false;
        }

        User otherUser = (User) other;

        return personalInfo.equals(otherUser.getPersonalInfo())
                && accountInfo.equals(otherUser.getAccountInfo())
                && isAuthorized == otherUser.isAuthorized();
    }
}
