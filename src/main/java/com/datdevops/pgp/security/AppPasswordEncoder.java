package com.datdevops.pgp.security;

import org.springframework.stereotype.Component;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

@Component
public class AppPasswordEncoder {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int SALT_LENGTH = 32;
    private static final int KEY_LENGTH = 256;
    private static final int ITERATIONS = 100000;

    public String encode(String rawPassword) {
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);

        try {
            KeySpec spec = new PBEKeySpec(rawPassword.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            byte[] hash = factory.generateSecret(spec).getEncoded();

            String saltBase64 = Base64.getEncoder().encodeToString(salt);
            String hashBase64 = Base64.getEncoder().encodeToString(hash);

            return saltBase64 + ":" + hashBase64;
        } catch (Exception e) {
            throw new RuntimeException("Error encoding password", e);
        }
    }

    public boolean matches(String rawPassword, String encodedPassword) {
        try {
            String[] parts = encodedPassword.split(":");
            if (parts.length != 2) {
                return false;
            }

            byte[] salt = Base64.getDecoder().decode(parts[0]);
            byte[] storedHash = Base64.getDecoder().decode(parts[1]);

            KeySpec spec = new PBEKeySpec(rawPassword.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            byte[] computedHash = factory.generateSecret(spec).getEncoded();

            return java.security.MessageDigest.isEqual(storedHash, computedHash);
        } catch (Exception e) {
            return false;
        }
    }
}