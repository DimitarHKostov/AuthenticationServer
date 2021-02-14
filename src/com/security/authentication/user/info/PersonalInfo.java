package com.security.authentication.user.info;

public class PersonalInfo {
    private final String firstName;
    private final String lastName;
    private final String email;

    public PersonalInfo(String firstName, String lastName, String email) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
    }

    public String getFirstName() {
        return this.firstName;
    }

    public String getLastName() {
        return this.lastName;
    }

    public String getEmail() {
        return this.email;
    }

    @Override
    public boolean equals(Object other) {
        if (other == null) {
            return false;
        }

        if (getClass() != other.getClass()) {
            return false;
        }

        PersonalInfo otherPersonalInfo = (PersonalInfo) other;

        return firstName.equals(otherPersonalInfo.getFirstName())
                && lastName.equals(otherPersonalInfo.getLastName())
                && email.equals(otherPersonalInfo.getEmail());
    }
}
