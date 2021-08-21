package com.hsbc.hk.simpleauth;

import com.hsbc.hk.AuthenticationService;
import com.hsbc.hk.Role;
import com.hsbc.hk.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Locale;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Authentication service")
class AuthenticationServiceTest {
    AuthenticationService service = null;

    public static final String User1 = "User1";
    public static final String User1WrongCase = "uSER1";
    public static final String Password1 = "½ÕÍ¥%nUÓãqpøEØEêãÖT»´6°¦VKÎú";
    public static final String Password2 = "Q65o:YH347rE''#l0kGoD0k(#\\\\Y_";
    public static final String Password3 = Password2;
    public static final String User2 = "User2";
    public static final String User3 = "User2";
    public static final String UserNonexistent = "UserNA";

    public static final String Role1 = "Role1";
    public static final String Role1WrongCase = "rolE1";
    public static final String Role2 = "Role2";
    public static final String Role3 = "Role2";
    public static final String RoleNonexistent = "RoleNonexistent";

    @BeforeEach
    void createNew() {
        service = new InMemoryAuthenticationService();
    }

    @Nested
    class WhenEmpty {

        @ParameterizedTest
        @ValueSource(strings={ User1, User2, User3, UserNonexistent })
        void noUsersFound(String username) {
            assertTrue(service.findUser(username).isEmpty(),
                    "service must contain no users");
        }

        @ParameterizedTest
        @ValueSource(strings={ Role1, Role2, Role3, RoleNonexistent })
        void noRolesFound(String role) {
            assertTrue(service.findRole(role).isEmpty(),
                    "service must contain no roles");
        }

    }

    @Nested
    class WhenRegisterUsersAndRoles {
        @BeforeEach
        void registerUsersAndRoles() {
            var user1 = service.createUser(User1, Password1);
            var user2 = service.createUser(User2, Password2);
            var user3 = service.createUser(User3, Password3);
            var role1= service.createRole(Role1);
            var role2 = service.createRole(Role2);
            var role3 = service.createRole(Role3);
            service.addRoleToUser(role1, user1);
            service.addRoleToUser(role2, user2);
            service.addRoleToUser(role1, user2);
        }

        @Test
        void findNonExistingRole() {
            assertTrue(service.findRole(RoleNonexistent).isEmpty(),
                    "non-existent role must not be found");
        }

        @Test
        void findNonExistingUser() {
           assertTrue(service.findUser(UserNonexistent).isEmpty(),
                   "non-existent user must not be found");
        }

        @ParameterizedTest
        @ValueSource(strings={ User1, User2, User3 })
        void usersFound(String username) {
            Optional<User> user = service.findUser(username);
            assertFalse(user.isEmpty(),
                    "service must return registered users");
            assertNotNull(user.get(), "user must not be null");
            assertNotNull(user.get().name(), "user name must not be null");
            assertEquals(username.toLowerCase(Locale.ROOT), user.get().name().toLowerCase(Locale.ROOT), "returned user must have same username");
        }

        @ParameterizedTest
        @ValueSource(strings={ Role1, Role2, Role3 })
        void rolesFound(String rolename) {
            Optional<Role> role = service.findRole(rolename);
            assertFalse(role.isEmpty(),
                    "service must return registered roles");
            assertNotNull(role.get(), "role must not be null");
            assertNotNull(role.get().name(), "role name must not be null");
            assertEquals(rolename.toLowerCase(Locale.ROOT), role.get().name().toLowerCase(Locale.ROOT), "returned role must have same rolename");
        }

        @Test
        void userFoundCaseInsensitive() {
            usersFound(User1WrongCase);
        }

        @Test
        void roleFoundCaseInsensitive() {
            rolesFound(Role1WrongCase);
        }

        // test found user's username
        // test found role's name

        @Nested
        class WhenAddingDuplicates {
            // add dup role
            // add dup user
            // add role again to user
        }


        @Nested
        class WhenAuthenticating {

            // test auth
            // test token
            // check roles

            @Nested
            class WhenInvalidated {
                // wont auth
            }
        }

        @Nested
        class WhenDeletingRolesAndUsers {
            // delete role, then authenticate and test users' their roles
            // delete user, test nonexistent, test authentication

            @Nested
            class WhenDeletingNonExistentRolesOrUsers {
                // delete again, nothing happens
            }
        }




    }
}