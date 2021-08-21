package com.hsbc.hk;

import java.util.Optional;
import java.util.Set;

public interface AuthenticationService {
    User createUser(String name, String password);

    void deleteUser(User user);

    Optional<User> findUser(String name);

    Role createRole(String name);

    Optional<Role> findRole(String name);

    void deleteRole(Role role);

    void addRoleToUser(Role role, User user);

    Token authenticate(String username, String password, String salt);

    void invalidate(Token token);

    boolean checkRole(Token token, Role role);

    Set<Role> getAllRoles(Token token);
}
