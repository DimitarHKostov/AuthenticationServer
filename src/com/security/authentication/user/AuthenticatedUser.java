package com.security.authentication.user;

import com.security.authentication.user.info.AccountInfo;
import com.security.authentication.user.info.PersonalInfo;

public abstract class AuthenticatedUser extends User {
    public AuthenticatedUser(AccountInfo accountInfo, PersonalInfo personalInfo) {
        super(accountInfo, personalInfo);
    }
}
