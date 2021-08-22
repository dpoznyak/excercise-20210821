package com.hsbc.hk.simpleauth;

import com.hsbc.hk.Role;
import com.hsbc.hk.User;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

class UserFacade implements  User {

    private final String username;

    UserFacade(String username) {
        this.username = username;
    }

    @Override
    public String name() {
        return username;
    }
}

class UserRecord {

    final String userName;
    private final byte[] salt;
    private final byte[] passwordHash;

    UserRecord(String userName, byte[] salt, byte[] passwordHash) {
        this.userName = toCanonicalName(userName);
        this.salt = salt;
        this.passwordHash = passwordHash;
    }


    public User asUserFacade() {
        return new UserFacade(userName);
    }

    ArrayList<Role> roles = new ArrayList<>();

    public List<Role> getRoles() {
        return roles;
    }

    public static String toCanonicalName(String username) {
        return username.toUpperCase(Locale.ROOT);
    }

    public byte[] getPasswordHash() {
        return passwordHash;
    }

    public byte[] getSalt() {
        return salt;
    }

    public String getUserName() {
        return userName;
    }
}
