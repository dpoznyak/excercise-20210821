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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class InMemoryAuthenticationService implements AuthenticationService {

    private static final int PASSWORD_HASHING_ITERATION_COUNT = 100; // TODO: change to e.g. 50000 for prod
    private static final int PASSWORD_SALT_LENGTH = 32;

    ConcurrentHashMap<String, UserRecord> users = new ConcurrentHashMap<>();
    ConcurrentHashMap<String, RoleImpl> roles = new ConcurrentHashMap<>();
    TokenService tokenService = new TokenService("Key213124134".getBytes(StandardCharsets.UTF_8), Duration.ofDays(1));
    SecureRandom saltGenerator = new SecureRandom();

    public InMemoryAuthenticationService()  {
    }

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

    Pattern usernamePattern = Pattern.compile("^\\w{3,}$");
    Pattern passwordPattern = Pattern.compile("^(?=.*\\d)(?=.*\\w)(?=.*\\W).{12,}$");
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
            var secretsFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            return secretsFactory.generateSecret(keySpec).getEncoded();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            throw new InternalException("Internal error: invalid key spec while generating user password hash", e);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new InternalException("Internal error: algorithm not found while generating user password hash", e);
        }
    }

    @Override
    public void deleteUser(User user) {
        users.remove(user.name());
    }

    @Override
    public Optional<User> findUser(String name) {
        UserRecord userInternal = findUserInternal(name);
        return userInternal == null ? Optional.empty() : Optional.of(userInternal.asUserFacade());
    }

    private UserRecord findUserInternal(String name) {
        return users.getOrDefault(UserRecord.toCanonicalName(name), null);
    }

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



    @Override
    public Optional<Role> findRole(String name) {
        return Optional.ofNullable(roles.getOrDefault(RoleImpl.toCanonicalName(name), null));

    }

    @Override
    public void deleteRole(Role role) {
        roles.remove(RoleImpl.toCanonicalName(role.name()));
    }

    @Override
    public void addRoleToUser(Role role, User user) {
        if (user == null || role == null) throw new IllegalArgumentException("User and role must be non-null");

        var record = findUserInternal(user.name());
        if (record != null) {
            List<Role> roles = record.getRoles();
            if (roles.contains(role)) {
                throw new InvalidOperationException("Specified role already assigned to this user");
            }
            roles.add( role);
        }
        // else user is deleted, just ignore (or, better, declare and throw an exception, but needs changing interface)
    }

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
            // TODO: log: user not found;
            return null;
        }
        if (!Arrays.equals(user.getPasswordHash(), calculatePasswordHash(password, user.getSalt()))) {
            // TODO: log: wrong password
            return null;
        }
        return tokenService.createToken(user, salt);
    }

    @Override
    public void invalidate(Token token) {
        tokenService.invalidate(token);
    }

    @Override
    public boolean checkRole(Token token, Role role) {

        var tokenData = validateToken(token);

        return Arrays.stream(tokenData.roles).anyMatch(role.name()::equals);
    }

    private TokenService.TokenData validateToken(Token token) {
        TokenService.TokenData tokenData = tokenService.validateToken(token);
        if (tokenData == null || findUserInternal(tokenData.username) == null)
            throw new InvalidTokenException("Provided token is invalid");

        return tokenData;
    }


    @Override
    public Set<Role> getAllRoles(Token token) {
        var tokenData = validateToken(token);

        return Arrays.stream(tokenData.roles)
                .map(this::findRole)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(Collectors.toSet());
    }
}
