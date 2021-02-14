package com.security.authentication.user.creator;

import com.security.authentication.user.UnauthenticatedUser;
import com.security.authentication.user.info.AccountInfo;
import com.security.authentication.user.info.PersonalInfo;
import com.security.authentication.validator.Validator;

import java.util.List;

public class UserCreator {
    public static UnauthenticatedUser create(List<String> parameters) {
        Validator.validateNotNull(parameters, "parameters");

        AccountInfo accountInfo = new AccountInfo(parameters.get(1), parameters.get(3));
        PersonalInfo personalInfo = new PersonalInfo(parameters.get(5), parameters.get(7), parameters.get(9));

        return new UnauthenticatedUser(accountInfo, personalInfo);
    }

    public static UnauthenticatedUser create(AccountInfo accountInfo, PersonalInfo personalInfo) {
        Validator.validateNotNull(accountInfo, "accountInfo");
        Validator.validateNotNull(personalInfo, "personalInfo");

        return new UnauthenticatedUser(accountInfo, personalInfo);
    }
}
