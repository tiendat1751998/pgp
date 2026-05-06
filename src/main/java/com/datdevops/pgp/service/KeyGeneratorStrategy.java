package com.datdevops.pgp.service;

import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;

/**
 * Strategy interface for key generation.
 * Allows adding new algorithms without modifying existing code (Open/Closed
 * Principle).
 */
public interface KeyGeneratorStrategy {

    String getKeyType();

    KeyMaterial generate();

    String getPublicKey(KeyMaterial keyMaterial);

    String getPrivateKey(KeyMaterial keyMaterial);

    record KeyMaterial(
            String publicKey,
            String privateKey,
            String keyFingerprint,
            Instant validFrom) {
        public static KeyMaterial create(String publicKey, String privateKey) {
            return new KeyMaterial(
                    publicKey,
                    privateKey,
                    generateFingerprint(publicKey),
                    Instant.now());
        }

        private static String generateFingerprint(String publicKey) {
            try {
                byte[] bytes = Base64.getDecoder().decode(publicKey);
                int hash = Arrays.hashCode(bytes);
                return Integer.toHexString(hash);
            } catch (Exception e) {
                return "FINGERPRINT_ERROR";
            }
        }
    }
}