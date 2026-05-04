package com.datdevops.pgp.service;

import jakarta.annotation.PostConstruct;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class SecretEncryptionService {

    @Value("${app.master-key:}")
    private String masterKey;

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final String FALLBACK_KEY_PREFIX = "default-master-key-must-be-32chars";

    private SecretKeySpec secretKey;

    public SecretEncryptionService() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @PostConstruct
    public void validate() {
        if (masterKey == null || masterKey.isBlank()) {
            throw new IllegalStateException("FATAL: APP_MASTER_KEY environment variable is not set. Cannot start with default key.");
        }
        if (masterKey.startsWith(FALLBACK_KEY_PREFIX)) {
            throw new IllegalStateException("FATAL: APP_MASTER_KEY cannot use default fallback value. Must be set to a secure key.");
        }
        if (masterKey.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalStateException("FATAL: APP_MASTER_KEY must be at least 32 bytes for AES-256.");
        }
        this.secretKey = deriveKey();
        System.out.println("✅ SecretEncryptionService initialized with secure key derivation");
    }

    public String encrypt(String plainText) throws Exception {
        if (secretKey == null) {
            throw new IllegalStateException("SecretEncryptionService not initialized. APP_MASTER_KEY not configured.");
        }
        byte[] iv = new byte[IV_LENGTH_BYTE];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        byte[] combined = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(cipherText, 0, combined, iv.length, cipherText.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    public String decrypt(String encryptedText) throws Exception {
        if (secretKey == null) {
            throw new IllegalStateException("SecretEncryptionService not initialized. APP_MASTER_KEY not configured.");
        }
        byte[] combined = Base64.getDecoder().decode(encryptedText);

        byte[] iv = new byte[IV_LENGTH_BYTE];
        byte[] cipherText = new byte[combined.length - IV_LENGTH_BYTE];

        System.arraycopy(combined, 0, iv, 0, IV_LENGTH_BYTE);
        System.arraycopy(combined, IV_LENGTH_BYTE, cipherText, 0, cipherText.length);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

        byte[] plainText = cipher.doFinal(cipherText);
        return new String(plainText, StandardCharsets.UTF_8);
    }

    private SecretKeySpec deriveKey() {
        try {
            HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new org.bouncycastle.crypto.digests.SHA256Digest());
            hkdf.init(new HKDFParameters(
                masterKey.getBytes(StandardCharsets.UTF_8),
                "pgp-master-key-salt".getBytes(StandardCharsets.UTF_8),
                "pgp-secret-encryption".getBytes(StandardCharsets.UTF_8)
            ));
            byte[] key = new byte[32];
            hkdf.generateBytes(key, 0, 32);
            return new SecretKeySpec(key, "AES");
        } catch (Exception e) {
            throw new IllegalStateException("Failed to derive key using HKDF: " + e.getMessage(), e);
        }
    }
}