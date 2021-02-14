package com.security.authentication.user;

import com.security.authentication.user.info.AccountInfo;
import com.security.authentication.user.info.PersonalInfo;

public class UnauthenticatedUser extends User {
    public UnauthenticatedUser(AccountInfo accountInfo, PersonalInfo personalInfo) {
        super(accountInfo, personalInfo);
        this.isAuthorized = false;
    }
}
