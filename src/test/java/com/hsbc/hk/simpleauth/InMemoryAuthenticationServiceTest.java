package com.hsbc.hk.simpleauth;

import com.hsbc.hk.AuthenticationService;
import com.hsbc.hk.Role;
import com.hsbc.hk.Token;
import com.hsbc.hk.User;
import com.hsbc.hk.errors.InvalidTokenException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Authentication service")
class AuthenticationServiceTest {
    AuthenticationService service = null;

    public static final String USER_1 = "User1";
    public static final String USER_1_WRONG_CASE = "uSER1";
    public static final String PASSWORD_1 = "½ÕÍ¥%nUÓãqpøEØEêãÖT»´6°¦VKÎú";
    public static final String PASSWORD_2 = "Q65o:YH347rE''#l0kGoD0k(#\\\\Y_";
    public static final String PASSWORD_3 = PASSWORD_2;
    public static final String PASSWORD_WRONG = "Password that is wrong!";
    public static final String USER_2 = "User2";
    public static final String USER_3 = "User3";
    public static final String USER_NONEXISTENT = "UserNA";

    public static final String ROLE_1 = "Role1";
    public static final String ROLE_1_WRONG_CASE = "rolE1";
    public static final String ROLE_2 = "Role2";
    public static final String ROLE_3 = "Role3";
    public static final String ROLE_NONEXISTENT = "RoleNonexistent";

    @BeforeEach
    void createNew() throws NoSuchAlgorithmException {
        service = new InMemoryAuthenticationService();
    }

    @Nested
    class WhenEmpty {

        @ParameterizedTest
        @ValueSource(strings={USER_1, USER_2, USER_3, USER_NONEXISTENT})
        void noUsersFound(String username) {
            assertTrue(service.findUser(username).isEmpty(),
                    "service must contain no users");
        }

        @ParameterizedTest
        @ValueSource(strings={ROLE_1, ROLE_2, ROLE_3, ROLE_NONEXISTENT})
        void noRolesFound(String role) {
            assertTrue(service.findRole(role).isEmpty(),
                    "service must contain no roles");

        }



    }

    @Nested
    class WhenRegisterUsersAndRoles {

        private User user1;
        private User user2;
        private User user3;
        private Role role1;
        private Role role2;
        private Role role3;

        @BeforeEach
        void registerUsersAndRoles() {
            user1 = service.createUser(USER_1, PASSWORD_1);
            user2 = service.createUser(USER_2, PASSWORD_2);
            user3 = service.createUser(USER_3, PASSWORD_3);
            role1 = service.createRole(ROLE_1);
            role2 = service.createRole(ROLE_2);
            role3 = service.createRole(ROLE_3);
            service.addRoleToUser(role1, user1);
            service.addRoleToUser(role2, user2);
            service.addRoleToUser(role1, user2);
        }

        @Test
        void allRolesCreated() {
            for (var role :
                    new Role[]{role1, role2, role3}) {
                assertNotNull(role, "All roles must be created");
            }
        }

        @Test
        void allUsersCreated() {
            for (var user :
                    new User[]{user1, user2, user3}) {
                assertNotNull(user, "All users must be created");
            }
        }

        @Nested
        class WhenSearchingRoles {
            @Test
            void findNonExistingRole() {
                assertTrue(service.findRole(ROLE_NONEXISTENT).isEmpty(),
                        "non-existent role must not be found");
            }

            @ParameterizedTest
            @ValueSource(strings={ROLE_1, ROLE_2, ROLE_3})
            void rolesFound(String rolename) {
                Optional<Role> role = service.findRole(rolename);
                assertFalse(role.isEmpty(),
                        "service must return registered roles");
                assertNotNull(role.get(), "role must not be null");
                assertNotNull(role.get().name(), "role name must not be null");
                assertEquals(rolename.toLowerCase(Locale.ROOT), role.get().name().toLowerCase(Locale.ROOT), "returned role must have same rolename");
            }

            @Test
            void roleFoundCaseInsensitive() {
                rolesFound(ROLE_1_WRONG_CASE);
            }
        }

        @Nested
        class WhenSearchingUsers {

            @Test
            void findNonExistingUser() {
                assertTrue(service.findUser(USER_NONEXISTENT).isEmpty(),
                        "non-existent user must not be found");
            }

            @ParameterizedTest
            @ValueSource(strings={USER_1, USER_2, USER_3})
            void usersFound(String username) {
                Optional<User> user = service.findUser(username);
                assertFalse(user.isEmpty(),
                        "service must return registered users");
                assertNotNull(user.get(), "user must not be null");
                assertNotNull(user.get().name(), "user name must not be null");
                assertEquals(username.toLowerCase(Locale.ROOT), user.get().name().toLowerCase(Locale.ROOT), "returned user must have same username");
            }

            @Test
            void userFoundCaseInsensitive() {
                usersFound(USER_1_WRONG_CASE);
            }
        }

        @Nested
        class WhenAddingDuplicates {
            // add dup role
            // add dup user
            // add role again to user
        }


        @Nested
        class WhenAuthenticating {


            private Token token1;
            private Token token1_2;
            private Token token2;
            private Token token3;



            @BeforeEach
            private void authenticate() {
                token1 = service.authenticate(USER_1, PASSWORD_1, getNewSaltForAuth());
                token1_2 = service.authenticate(USER_1, PASSWORD_1, getNewSaltForAuth());
                token2 = service.authenticate(USER_2, PASSWORD_2, getNewSaltForAuth());
                token3 = service.authenticate(USER_3, PASSWORD_3, getNewSaltForAuth());
            }

            @Test
            void authenticateSuccessfully() {
                authenticate();
                assertNotNull(token1, "Authenticate expected to succeed");
                assertNotNull(token2, "Authenticate expected to succeed");
                assertNotNull(token3, "Authenticate expected to succeed");
            }

            @Test
            void checkRolesInTokens() {


                checkRolesForToken(token1, Arrays.asList(role1));
                checkRolesForToken(token1_2, Arrays.asList(role1));
                checkRolesForToken(token2, Arrays.asList(role1, role2));
                checkRolesForToken(token3, Arrays.asList());
            }

            private void checkRolesForToken(Token token, List<Role> roles) {
                for (var r : roles) {
                    assertTrue(service.checkRole(token, r), "User expected to be in role");
                }

                assertFalse(service.checkRole(token, role3), "User NOT expected to be in role");

                assertEquals(
                        new HashSet<>(roles.stream().map(r -> r.name()).collect(Collectors.toSet())),
                        service.getAllRoles(token).stream().map(r -> r.name()).collect(Collectors.toSet()),
                        "Token expected to return correct roles");
            }


            @Nested
            class WhenInvalidated {
                @BeforeEach
                void invalidateToken() {
                    service.invalidate(token1_2);
                }

                @Test
                void invalidatedTokenThrows() {

                    assertThrows(InvalidTokenException.class, () -> service.getAllRoles(token1_2));
                    assertThrows(InvalidTokenException.class, () -> service.checkRole(token1_2, role1));
                    assertThrows(InvalidTokenException.class, () -> service.checkRole(token1_2, role3));
                }

                @Test
                void validTokenForSameUserIsFine() {
                    checkRolesForToken(token1, Arrays.asList(role1));

                }

            }


            @Nested
            class WhenDeletingRoles {

                @BeforeEach
                void deleteRole1() {
                    service.deleteRole(role1);
                }

                @Test
                void existingTokensDontHaveRole1() {
                    checkRolesForToken(token1, Arrays.asList());
                    checkRolesForToken(token2, Arrays.asList(role2));
                }

                @Test
                void newTokensDontHaveRole1() {
                    var token = service.authenticate(USER_1, PASSWORD_1, getNewSaltForAuth());
                    checkRolesForToken(token, Arrays.asList());
                }

                @Test
                void role1NotFound() {
                    assertTrue(service.findRole(ROLE_1).isEmpty(),
                            "deleted role must not be found");
                }

            }

            @Nested
            class WhenDeletingUsers {
                @BeforeEach
                void deleteUser1() {
                    service.deleteUser(user1);
                }

                @Test
                void cannotAuthenticate() {
                    var token = service.authenticate(USER_1, PASSWORD_1, getNewSaltForAuth());
                    assertNull(token, "Authenticate expected to fail for deleted user");

                }

                @Test
                void existingTokenNoLongerValid() {
                    assertThrows(InvalidTokenException.class, () -> service.getAllRoles(token1));
                    assertThrows(InvalidTokenException.class, () -> service.checkRole(token1, role1));
                    assertThrows(InvalidTokenException.class, () -> service.checkRole(token1, role3));
                }

                @Test
                void user1NotFound() {
                    assertTrue(service.findUser(USER_1).isEmpty(),
                            "deleted user must not be found");
                }
            }

            @Test
            void authenticateUnsuccessfully() {
                var token = service.authenticate(USER_1, PASSWORD_WRONG, getNewSaltForAuth());
                assertNull(token, "Authenticate expected to fail");
            }

            @Test
            void authenticateUnknownUser() {
                var token = service.authenticate(USER_NONEXISTENT, PASSWORD_1, getNewSaltForAuth());
                assertNull(token, "Authenticate expected to fail");
            }

            @Nested
            class WhenTamperingWithToken {
                @BeforeEach
                void hackTokens() throws IllegalAccessException, NoSuchFieldException {
                    var dataField= token1.getClass().getDeclaredField("data");
                    var data1 = dataField.get(token1);
                    var usernameField = data1.getClass().getDeclaredField("username");
                    usernameField.setAccessible(true);
                    usernameField.set(data1, "User2");

                    var data1_2 = dataField.get(token1_2);
                    var rolesField = data1_2.getClass().getDeclaredField("roles");
                    rolesField.setAccessible(true);
                    rolesField.set(data1_2, new String[]{ROLE_3});
                }

                @Test
                void token1NoLongerValid() {
                    assertThrows(InvalidTokenException.class, () -> service.getAllRoles(token1));
                    assertThrows(InvalidTokenException.class, () -> service.checkRole(token1, role1));
                }
                @Test
                void token1_2NoLongerValid() {
                    assertThrows(InvalidTokenException.class, () -> service.getAllRoles(token1_2));
                    assertThrows(InvalidTokenException.class, () -> service.checkRole(token1_2, role1));
                }
            }
        }



        int saltCounter = 0;
        String getNewSaltForAuth() {
            saltCounter++;
            return String.format("Salt_%d", saltCounter);
        }


    }
}