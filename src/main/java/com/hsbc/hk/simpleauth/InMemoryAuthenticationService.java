package com.hsbc.hk.simpleauth;

import com.hsbc.hk.AuthenticationService;
import com.hsbc.hk.Role;
import com.hsbc.hk.Token;
import com.hsbc.hk.User;

import java.util.*;

public class InMemoryAuthenticationService implements AuthenticationService {

    HashMap<String, User> users = new HashMap<>();
    HashMap<String, Role> roles = new HashMap<>();

    static class UserImpl implements com.hsbc.hk.User {

        final String userName;

        UserImpl(String userName) {
            this.userName = toCanonicalName(userName);
        }

        @Override
        public String name() {
            return userName;
        }

        ArrayList<RoleImpl> roles = new ArrayList<>();
        public List<RoleImpl> getRoles() { return roles; }

        public static String toCanonicalName(String username) {
            return username.toUpperCase(Locale.ROOT);
        }
    }

    static class RoleImpl implements com.hsbc.hk.Role {

        final String roleName;

        RoleImpl(String roleName) {
            this.roleName = toCanonicalName(roleName);
        }

        @Override
        public String name() {
            return roleName;
        }

        public static String toCanonicalName(String roleName) {
            return roleName.toUpperCase(Locale.ROOT);
        }
    }


    @Override
    public User createUser(String name, String password) {
        var user = new UserImpl(name);
        return users.put(user.name(), user);
    }

    @Override
    public void deleteUser(User user) {
        users.remove(user.name());
    }

    @Override
    public Optional<User> findUser(String name) {
        return Optional.ofNullable(users.getOrDefault(UserImpl.toCanonicalName(name), null));
    }

    @Override
    public Role createRole(String name) {
        var role = new RoleImpl(name);
        return roles.put(role.name(), role);
    }

    @Override
    public Optional<Role> findRole(String name) {
        return Optional.ofNullable(roles.getOrDefault(RoleImpl.toCanonicalName(name), null));

    }

    @Override
    public void deleteRole(Role role) {
        roles.remove(role.name());
    }

    @Override
    public void addRoleToUser(Role role, User user) {

    }

    @Override
    public Token authenticate(String username, String password, String salt) {
        return null;
    }

    @Override
    public void invalidate(Token token) {

    }

    @Override
    public boolean checkRole(Token token, Role role) {
        return false;
    }

    @Override
    public Set<Role> getAllRoles(Token token) {
        return null;
    }
}
