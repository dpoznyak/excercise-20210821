package com.hsbc.hk.simpleauth;

import com.hsbc.hk.AuthenticationService;
import com.hsbc.hk.Role;
import com.hsbc.hk.Token;
import com.hsbc.hk.User;
import com.hsbc.hk.errors.InternalException;
import com.hsbc.hk.errors.InvalidOperationException;
import com.hsbc.hk.errors.InvalidTokenException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

public class InMemoryAuthenticationService implements AuthenticationService {

    private static final int PASSWORD_HASHING_ITERATION_COUNT = 50000; // change to lower value for faster test execution
    private static final int PASSWORD_SALT_LENGTH = 32;
    private static final String PASSWORD_HASHING_ALGO = "PBKDF2WithHmacSHA1";

    final ConcurrentHashMap<String, UserRecord> users = new ConcurrentHashMap<>();
    final ConcurrentHashMap<String, RoleImpl> roles = new ConcurrentHashMap<>();
    final TokenService tokenService;
    final SecureRandom saltGenerator = new SecureRandom();

    public InMemoryAuthenticationService(String secretKey, Duration expiryTimeout)  {
        tokenService = new TokenService(secretKey.getBytes(StandardCharsets.UTF_8), expiryTimeout);
    }

    /**
     * User CRUD: create user.
     * Note: created user will have their username canonized (converted to uppercase) as a policy
     * @throws IllegalArgumentException if name or password are invalid (empty or not satisfying policies)
     * @throws InvalidOperationException if user already exists
     * @throws InternalException if cryptography fails
     */
    @Override
    public User createUser(String name, String password) {
        if (null == name || name.isBlank() || !isUsernameValid(name))  {
            throw new IllegalArgumentException("User name cannot be blank");
        }
        if (null == password || password.isBlank() ) {
            throw new IllegalArgumentException("Password cannot be blank");
        }
        var salt = generatePasswordSalt();
        var hash = calculatePasswordHash(password, salt);
        var user = new UserRecord(name, salt, hash);
        UserRecord oldUser = users.putIfAbsent(user.getUserName(), user);
        if (oldUser != null) {
            throw new InvalidOperationException("Specified user already exists");
        }
        if (!isPasswordValid(password)) {
            throw new IllegalArgumentException("Password is too simple");
        }
        return user.asUserFacade();
    }

    final Pattern usernamePattern = Pattern.compile("^\\w{3,}$");
    final Pattern passwordPattern = Pattern.compile("^(?=.*\\d)(?=.*\\w)(?=.*\\W).{12,}$");
    private boolean isUsernameValid(String name) {
        // enforce any username policies here. Example:
        return usernamePattern.matcher(name).matches();
    }
    private boolean isPasswordValid(String password) {
        // enforce any password policies here. Example:
        return passwordPattern.matcher(password).matches();
    }


    private byte[] generatePasswordSalt() {
        var salt = new byte[PASSWORD_SALT_LENGTH];
        saltGenerator.nextBytes(salt);
        return salt;
    }

    private byte[] calculatePasswordHash(String password, byte[] salt) {

        var keySpec = new PBEKeySpec(password.toCharArray(), salt,
                PASSWORD_HASHING_ITERATION_COUNT,
                128);
        try {
            var secretsFactory = SecretKeyFactory.getInstance(PASSWORD_HASHING_ALGO);
            return secretsFactory.generateSecret(keySpec).getEncoded();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            throw new InternalException("Internal error: invalid key spec while generating user password hash", e);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new InternalException("Internal error: algorithm not found while generating user password hash", e);
        }
    }

    /**
     * User CRUD: deletes user if exists
     */
    @Override
    public void deleteUser(User user) {
        users.remove(user.name());
    }

    /**
     * User CRUD: finds user by name
     */
    @Override
    public Optional<User> findUser(String name) {
        UserRecord userInternal = findUserInternal(name);
        return userInternal == null ? Optional.empty() : Optional.of(userInternal.asUserFacade());
    }

    private UserRecord findUserInternal(String name) {
        return users.getOrDefault(UserRecord.toCanonicalName(name), null);
    }

    /**
     * Role CRUD: create role
     * @throws IllegalArgumentException if role name is blank
     * @throws InvalidOperationException if role already exists
     */
    @Override
    public Role createRole(String name) {
        if (null == name || name.isBlank() ) {
            throw new IllegalArgumentException("Role name cannot be blank");
        }

        var role = new RoleImpl(name);
        var oldRole = roles.putIfAbsent(RoleImpl.toCanonicalName(name), role);
        if (oldRole != null) {
            throw new InvalidOperationException("Specified role already exists");
        }
        return role;
    }


    /**
     * Role CRUD: Find by name
     */
    @Override
    public Optional<Role> findRole(String name) {
        return Optional.ofNullable(roles.getOrDefault(RoleImpl.toCanonicalName(name), null));

    }

    /**
     * Role CRUD: delete role if exists
     * @param role
     */
    @Override
    public void deleteRole(Role role) {
        roles.remove(RoleImpl.toCanonicalName(role.name()));
        for (var user : users.values()) {
            user.getRoles().remove(role);
        }
    }

    /**
     * Adds user to specified role
     * @throws InvalidOperationException if user or role not found, or user already assigned given role
     * @throws IllegalArgumentException if user or role are null
     */
    @Override
    public void addRoleToUser(Role role, User user) {
        if (user == null || role == null) throw new IllegalArgumentException("User and role must be non-null");

        var record = findUserInternal(user.name());
        if (record == null) {
            throw new InvalidOperationException("User not found");
        }
        if (!roles.containsKey(RoleImpl.toCanonicalName(role.name()))) {
            throw new InvalidOperationException("Role not found");
        }

        List<Role> roles = record.getRoles();
        if (roles.contains(role)) {
            throw new InvalidOperationException("Specified role already assigned to this user");
        }
        roles.add( role);


    }

    /**
     * Performs authentication and returns token if successful
     * @param salt used for hashing. Caller should guarantee uniqueness of salt with each call to avoid
     *             token collision. If salt is reused for the same username, resulting tokens may be
     *             exactly same, so any subsequent invalidation will apply to both tokens
     * @return Token if successful; null if not successful (user not found or password is invalid)
     * @throws IllegalArgumentException when username or salt are blank
     */
    @Override
    public Token authenticate(String username, String password, String salt) {
        if (null == username || username.isBlank()) {
            throw new IllegalArgumentException("User name cannot be blank");
        }
        if (null == salt || salt.isBlank()) {
            throw new IllegalArgumentException("Salt cannot be blank");
        }

        var user = findUserInternal(username);
        if (user == null || password == null) {
            return null;
        }
        if (!Arrays.equals(user.getPasswordHash(), calculatePasswordHash(password, user.getSalt()))) {
            return null;
        }
        return tokenService.createToken(user, salt);
    }

    /**
     * Invalidates given token. Subsequent calls to checkRole or getAllRoles will fail with InvalidTokenException
     */
    @Override
    public void invalidate(Token token) {
        tokenService.invalidate(token);
    }

    /**
     * Checks if user presenting the token currently belongs to the role
     * @return true if user is currently assigned given role
     * @throws InvalidTokenException if token is expired, corrupted, or ivalidated
     * @throws IllegalArgumentException if token or role is null
     * @throws InvalidOperationException if user was deleted after token was issued
     */
    @Override
    public boolean checkRole(Token token, Role role) {
        if (null == role) {
            throw new IllegalArgumentException("Role must be specified");
        }
        var tokenData = validateToken(token);
        var user = findUserInternal(tokenData.username);
        if (user == null) {
            throw new InvalidOperationException("User not found");
        }

        return user.getRoles().stream().anyMatch(r -> r.name().equals(role.name()));
    }

    private TokenService.TokenData validateToken(Token token) {
        TokenService.TokenData tokenData = tokenService.validateToken(token);
        if (tokenData == null || findUserInternal(tokenData.username) == null)
            throw new InvalidTokenException("Provided token is invalid");

        return tokenData;
    }


    /**
     * Returns all roles currently assigned to the user
     * @param token
     * @return
     */
    @Override
    public Set<Role> getAllRoles(Token token) {
        var tokenData = validateToken(token);
        var user = findUserInternal(tokenData.username);
        if (user == null) {
            throw new InvalidOperationException("User not found");
        }

        return new HashSet<>(user.getRoles());
    }
}
