package com.datdevops.pgp.service;

import jakarta.annotation.PostConstruct;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Service for encrypting application-level secrets (e.g., Keystore passwords).
 * Hardened with HKDF key derivation and secure memory practices.
 */
@Service
public class SecretEncryptionService {

    private static final Logger log = LoggerFactory.getLogger(SecretEncryptionService.class);
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Value("${app.master-key:}")
    private String masterKeyConfig;

    @Value("${app.master-key-salt:}")
    private String masterKeySalt;

    private SecretKeySpec secretKey;

    public SecretEncryptionService() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @PostConstruct
    public void validate() {
        if (masterKeyConfig == null || masterKeyConfig.isBlank()) {
            throw new IllegalStateException("FATAL: app.master-key is not configured. System cannot safely store secrets.");
        }
        
        // Fix Logic Bug #172: Salt must be persistent to prevent data loss on restart
        if (masterKeySalt == null || masterKeySalt.isBlank()) {
            log.error("FATAL: app.master-key-salt is missing. All encrypted secrets will be lost if salt changes.");
            throw new IllegalStateException("FATAL: app.master-key-salt must be configured for persistent encryption.");
        }

        char[] masterKeyChars = masterKeyConfig.toCharArray();
        try {
            if (masterKeyChars.length < 32) {
                throw new IllegalStateException("FATAL: app.master-key must be at least 32 characters for AES-256.");
            }
            
            // Fix Memory Security #171: Convert chars to bytes without creating an immutable String object
            ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(masterKeyChars));
            byte[] masterKeyBytes = new byte[byteBuffer.remaining()];
            byteBuffer.get(masterKeyBytes);
            
            try {
                this.secretKey = deriveKey(masterKeyBytes, masterKeySalt);
                log.info("SecretEncryptionService initialized with persistent HKDF derivation");
            } finally {
                // Securely wipe sensitive material from memory
                Arrays.fill(masterKeyBytes, (byte) 0);
                if (byteBuffer.hasArray()) {
                    Arrays.fill(byteBuffer.array(), (byte) 0);
                }
            }
        } finally {
            Arrays.fill(masterKeyChars, '\0');
            // Suggesting user to use env variables instead of properties file for these
            masterKeyConfig = null; 
        }
    }

    public String encrypt(String plainText) throws Exception {
        if (plainText == null) return null;
        byte[] bytes = plainText.getBytes(StandardCharsets.UTF_8);
        try {
            return encrypt(bytes);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    public String encrypt(byte[] plainText) throws Exception {
        if (secretKey == null) {
            throw new IllegalStateException("SecretEncryptionService not initialized.");
        }
        if (plainText == null) return null;

        byte[] iv = new byte[IV_LENGTH_BYTE];
        SECURE_RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

        byte[] cipherText = cipher.doFinal(plainText);

        byte[] combined = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(cipherText, 0, combined, iv.length, cipherText.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    public String decrypt(String encryptedText) throws Exception {
        byte[] decrypted = decryptToBytes(encryptedText);
        if (decrypted == null) return null;
        try {
            return new String(decrypted, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(decrypted, (byte) 0);
        }
    }

    public byte[] decryptToBytes(String encryptedText) throws Exception {
        if (secretKey == null) {
            throw new IllegalStateException("SecretEncryptionService not initialized.");
        }
        if (encryptedText == null) return null;

        byte[] combined = Base64.getDecoder().decode(encryptedText);
        if (combined.length < IV_LENGTH_BYTE) {
            throw new IllegalArgumentException("Invalid encrypted text - too short");
        }

        byte[] iv = new byte[IV_LENGTH_BYTE];
        byte[] cipherText = new byte[combined.length - IV_LENGTH_BYTE];

        System.arraycopy(combined, 0, iv, 0, IV_LENGTH_BYTE);
        System.arraycopy(combined, IV_LENGTH_BYTE, cipherText, 0, cipherText.length);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

        return cipher.doFinal(cipherText);
    }

    private SecretKeySpec deriveKey(byte[] masterKeyBytes, String salt) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(
                masterKeyBytes,
                salt.getBytes(StandardCharsets.UTF_8),
                "pgp-secret-encryption".getBytes(StandardCharsets.UTF_8)));
        byte[] key = new byte[32];
        hkdf.generateBytes(key, 0, 32);
        return new SecretKeySpec(key, "AES");
    }
}