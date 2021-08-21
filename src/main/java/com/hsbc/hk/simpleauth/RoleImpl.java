package com.hsbc.hk.simpleauth;

import java.util.Locale;

class RoleImpl implements com.hsbc.hk.Role {

    final String roleName;

    RoleImpl(String roleName) {
        this.roleName = roleName;
    }

    @Override
    public String name() {
        return roleName;
    }

    public static String toCanonicalName(String roleName) {
        return roleName.toUpperCase(Locale.ROOT);
    }
}
