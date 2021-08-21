package com.hsbc.hk.simpleauth;

import com.hsbc.hk.Token;
import com.hsbc.hk.errors.InternalException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.TemporalAmount;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

public class TokenService {

    private byte[] secretKey;
    private TemporalAmount expiryTimeout;

    public TokenService(byte[] secretKey, TemporalAmount expiryTimeout) {
        this.secretKey = secretKey;
        this.expiryTimeout = expiryTimeout;
    }

    public static class TokenData {
        String username;
        String salt;
        LocalDateTime expiryDate;
        String[] roles;

        public String getUsername() {
            return username;
        }

        public String getSalt() {
            return salt;
        }

        public LocalDateTime getExpiryDate() {
            return expiryDate;
        }

        public String[] getRoles() {
            return roles;
        }

        public TokenData(String username, String salt, LocalDateTime expiryDate, String[] roles) {
            this.username = username;
            this.salt = salt;
            this.expiryDate = expiryDate;
            this.roles = roles;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            TokenData tokenData = (TokenData) o;
            return username.equals(tokenData.username) && salt.equals(tokenData.salt) && expiryDate.equals(tokenData.expiryDate) && Arrays.equals(roles, tokenData.roles);
        }

        @Override
        public int hashCode() {
            int result = Objects.hash(username, salt, expiryDate);
            result = 31 * result + Arrays.hashCode(roles);
            return result;
        }
    }

    static class TokenImpl implements Token {
        TokenData data;
        byte[] mac;

        public TokenData getData() {
            return data;
        }

        public byte[] getMac() {
            return mac;
        }

        public TokenImpl(TokenData data, byte[] mac) {
            this.data = data;
            this.mac = mac;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            TokenImpl token = (TokenImpl) o;
            return data.equals(token.data) && Arrays.equals(mac, token.mac);
        }

        @Override
        public int hashCode() {
            int result = Objects.hash(data);
            result = 31 * result + Arrays.hashCode(mac);
            return result;
        }
    }

    private static final String MAC_ALGO = "HmacSHA512";

    public Token createToken(UserRecord user, String salt) {

        var data = new TokenData(user.getUserName(), salt, LocalDateTime.now().plus(expiryTimeout),
                user.roles.stream().map(r -> r.name()).toArray(String[]::new));

        return new TokenImpl(data, calculateHmac(data));
    }

    public TokenData validateToken(Token token) {
        if (invalidatedTokens.containsKey(token)) {
            return null;
        }

        if (!(token instanceof TokenImpl)) return null;

        var tokenImpl = (TokenImpl)token;

        if (!Arrays.equals(tokenImpl.mac, calculateHmac(tokenImpl.data))) return null;

        if (!tokenImpl.data.expiryDate.isAfter(LocalDateTime.now())) return null;

        return tokenImpl.data;
    }

    byte[] calculateHmac(TokenData data) {
        try {
            var mac = Mac.getInstance(MAC_ALGO);
            var keySpec = new SecretKeySpec(secretKey, MAC_ALGO);
            mac.init(keySpec);
            mac.update(String.format("%s.%s.%d.%s",
                            data.username,
                            data.salt,
                            data.expiryDate.atZone(ZoneId.systemDefault()).toEpochSecond(),
                            String.join(",", data.roles))
                    .getBytes(StandardCharsets.UTF_8));
            return mac.doFinal();

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            throw new InternalException("Internal error: failed to create HMAC for token generation", e);
        }
    }



    //TODO: remove entries when they expire
    ConcurrentHashMap<Token, Token> invalidatedTokens = new ConcurrentHashMap<>();

    public void invalidate(Token token) {
        invalidatedTokens.putIfAbsent(token, token);
    }
}

