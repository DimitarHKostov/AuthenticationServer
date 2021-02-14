package com.security.authentication.user;

import com.security.authentication.user.info.AccountInfo;
import com.security.authentication.user.info.PersonalInfo;

public class Admin extends AuthenticatedUser {
    public Admin(AccountInfo accountInfo, PersonalInfo personalInfo) {
        super(accountInfo, personalInfo);
        this.isAuthorized = true;
    }
}
