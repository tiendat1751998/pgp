package com.datdevops.pgp.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.time.Instant;
import java.util.Base64;

@Component
public class JwtTokenProvider {

    private static final Logger log = LoggerFactory.getLogger(JwtTokenProvider.class);
    private static final String ALGORITHM = "AES";
    private static final int KEY_SIZE_BYTES = 32;
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int IV_SIZE = 12;
    private static final int TAG_SIZE = 128;

    private final SecretKey secretKey;

    public JwtTokenProvider(
            @Value("${app.jwt.secret-key:}") String jwtSecretKey,
            @Value("${app.jwt.generate-on-missing:true}") boolean generateOnMissing) {

        SecretKey generatedKey = null;

        if (jwtSecretKey != null && !jwtSecretKey.isEmpty()) {
            try {
                byte[] keyBytes = Base64.getDecoder().decode(jwtSecretKey);
                if (keyBytes.length == KEY_SIZE_BYTES) {
                    generatedKey = new SecretKeySpec(keyBytes, ALGORITHM);
                    log.info("JWT secret key loaded from configuration");
                } else {
                    log.warn("JWT secret key length invalid (expected {} bytes)", KEY_SIZE_BYTES);
                }
            } catch (IllegalArgumentException e) {
                log.warn("JWT secret key not valid Base64: {}", e.getMessage());
            }
        }

        if (generatedKey == null) {
            if (generateOnMissing) {
                log.warn("No JWT secret key configured - generating new key. RESTART WILL INVALIDATE ALL TOKENS!");
                generatedKey = generateKey();
            } else {
                throw new IllegalStateException("JWT secret key not configured and generate-on-missing is disabled");
            }
        }

        this.secretKey = generatedKey;
    }

    private SecretKey generateKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            keyGenerator.init(KEY_SIZE_BYTES * 8, new SecureRandom());
            return keyGenerator.generateKey();
        } catch (Exception e) {
            throw new RuntimeException("Error generating key", e);
        }
    }

    public String generateToken(String username, String role, long expirationMillis) {
        long expiry = Instant.now().plusMillis(expirationMillis).getEpochSecond();
        String payload = username + ":" + role + ":" + expiry;

        try {
            byte[] iv = new byte[IV_SIZE];
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_SIZE, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

            byte[] encrypted = cipher.doFinal(payload.getBytes());

            byte[] combined = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);

            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            throw new RuntimeException("Error generating token", e);
        }
    }

    public boolean validateToken(String token) {
        try {
            String payload = extractPayload(token);
            if (payload == null) return false;

            String[] parts = payload.split(":");
            if (parts.length != 2) return false;

            long expiry = Long.parseLong(parts[1]);
            return Instant.now().getEpochSecond() < expiry;
        } catch (Exception e) {
            return false;
        }
    }

    public String getUsernameFromToken(String token) {
        try {
            String payload = extractPayload(token);
            if (payload == null) return null;

            String[] parts = payload.split(":");
            return parts[0];
        } catch (Exception e) {
            return null;
        }
    }

    public String getRoleFromToken(String token) {
        try {
            String payload = extractPayload(token);
            if (payload == null) return null;

            String[] parts = payload.split(":");
            return parts.length > 1 ? parts[1] : "USER";
        } catch (Exception e) {
            return null;
        }
    }

    private String extractPayload(String token) {
        try {
            byte[] combined = Base64.getDecoder().decode(token);

            byte[] iv = new byte[IV_SIZE];
            byte[] encrypted = new byte[combined.length - IV_SIZE];
            System.arraycopy(combined, 0, iv, 0, IV_SIZE);
            System.arraycopy(combined, IV_SIZE, encrypted, 0, encrypted.length);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_SIZE, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted);
        } catch (Exception e) {
            return null;
        }
    }

    public String getSecretKeyBase64() {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }
}