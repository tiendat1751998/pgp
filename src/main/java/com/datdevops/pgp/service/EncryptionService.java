package com.datdevops.pgp.service;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

@Service
public class EncryptionService {

    private static final int KEY_SIZE_BITS = 256;
    private static final int MAC_SIZE_BITS = 128;
    private static final int NONCE_SIZE_BYTES = 12;
    private static final String RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    private final SecureRandom secureRandom;
    private final Cache<String, PublicKey> publicKeyCache;
    private final Cache<String, PrivateKey> privateKeyCache;

    public EncryptionService() {
        this.secureRandom = new SecureRandom();
        this.publicKeyCache = Caffeine.newBuilder()
                .maximumSize(1000)
                .expireAfterAccess(1, TimeUnit.HOURS)
                .build();
        this.privateKeyCache = Caffeine.newBuilder()
                .maximumSize(1000)
                .expireAfterAccess(1, TimeUnit.HOURS)
                .build();
    }

    public EncryptionResult encrypt(byte[] plaintext, byte[] key, byte[] associatedData) {
        if (key.length != KEY_SIZE_BITS / 8) {
            throw new IllegalArgumentException("Key must be " + KEY_SIZE_BITS / 8 + " bytes long");
        }

        byte[] nonce = new byte[NONCE_SIZE_BYTES];
        secureRandom.nextBytes(nonce);

        AEADBlockCipher cipher = new GCMBlockCipher(new AESEngine());
        KeyParameter keyParam = new KeyParameter(key);

        AEADParameters aeadParams;
        if (associatedData != null && associatedData.length > 0) {
            aeadParams = new AEADParameters(keyParam, MAC_SIZE_BITS, nonce, associatedData);
        } else {
            aeadParams = new AEADParameters(keyParam, MAC_SIZE_BITS, nonce);
        }

        cipher.init(true, aeadParams);

        byte[] output = new byte[cipher.getOutputSize(plaintext.length)];
        int length = cipher.processBytes(plaintext, 0, plaintext.length, output, 0);

        try {
            length += cipher.doFinal(output, length);
        } catch (InvalidCipherTextException e) {
            throw new IllegalStateException("Encryption failed", e);
        }

        byte[] ciphertext = Arrays.copyOfRange(output, 0, length - MAC_SIZE_BITS / 8);
        byte[] mac = Arrays.copyOfRange(output, length - MAC_SIZE_BITS / 8, length);

        return new EncryptionResult(ciphertext, nonce, mac);
    }

    public byte[] decrypt(byte[] ciphertext, byte[] key, byte[] nonce, byte[] mac, byte[] associatedData) {
        if (key.length != KEY_SIZE_BITS / 8) {
            throw new IllegalArgumentException("Key must be " + KEY_SIZE_BITS / 8 + " bytes long");
        }
        if (nonce.length != NONCE_SIZE_BYTES) {
            throw new IllegalArgumentException("Nonce must be " + NONCE_SIZE_BYTES + " bytes long");
        }
        if (mac.length != MAC_SIZE_BITS / 8) {
            throw new IllegalArgumentException("MAC must be " + MAC_SIZE_BITS / 8 + " bytes long");
        }

        AEADBlockCipher cipher = new GCMBlockCipher(new AESEngine());
        KeyParameter keyParam = new KeyParameter(key);

        AEADParameters aeadParams;
        if (associatedData != null && associatedData.length > 0) {
            aeadParams = new AEADParameters(keyParam, MAC_SIZE_BITS, nonce, associatedData);
        } else {
            aeadParams = new AEADParameters(keyParam, MAC_SIZE_BITS, nonce);
        }

        cipher.init(false, aeadParams);

        byte[] input = new byte[ciphertext.length + mac.length];
        System.arraycopy(ciphertext, 0, input, 0, ciphertext.length);
        System.arraycopy(mac, 0, input, ciphertext.length, mac.length);

        byte[] output = new byte[cipher.getOutputSize(input.length)];
        int length = cipher.processBytes(input, 0, input.length, output, 0);

        try {
            length += cipher.doFinal(output, length);
        } catch (InvalidCipherTextException e) {
            throw new IllegalStateException("Decryption failed: " + e.getMessage(), e);
        }

        return Arrays.copyOf(output, length);
    }

    public byte[] encryptSessionKey(byte[] sessionKey, RSAKeyParameters rsaPublicKey) throws Exception {
        PublicKey publicKey = convertBCToJavaPublicKey(rsaPublicKey);
        return encryptSessionKey(sessionKey, publicKey);
    }

    public byte[] decryptSessionKey(byte[] encryptedSessionKey, RSAKeyParameters rsaPrivateKey) throws Exception {
        PrivateKey privateKey = convertBCToJavaPrivateKey(rsaPrivateKey);
        return decryptSessionKey(encryptedSessionKey, privateKey);
    }

    public byte[] encryptSessionKey(byte[] sessionKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(sessionKey);
    }

    public byte[] decryptSessionKey(byte[] encryptedSessionKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedSessionKey);
    }

    private PublicKey convertBCToJavaPublicKey(RSAKeyParameters bcKey) throws Exception {
        String cacheKey = bcKey.getModulus().toString(16) + ":" + bcKey.getExponent().toString(16);
        PublicKey cached = publicKeyCache.getIfPresent(cacheKey);
        if (cached != null) {
            return cached;
        }
        
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec spec = new RSAPublicKeySpec(bcKey.getModulus(), bcKey.getExponent());
        PublicKey generated = factory.generatePublic(spec);
        publicKeyCache.put(cacheKey, generated);
        return generated;
    }

    private PrivateKey convertBCToJavaPrivateKey(RSAKeyParameters bcKey) throws Exception {
        String cacheKey = bcKey.getModulus().toString(16) + ":" + bcKey.getExponent().toString(16);
        PrivateKey cached = privateKeyCache.getIfPresent(cacheKey);
        if (cached != null) {
            return cached;
        }

        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec spec = new RSAPrivateKeySpec(bcKey.getModulus(), bcKey.getExponent());
        PrivateKey generated = factory.generatePrivate(spec);
        privateKeyCache.put(cacheKey, generated);
        return generated;
    }

    public static class EncryptionResult {
        private final byte[] ciphertext;
        private final byte[] nonce;
        private final byte[] mac;

        public EncryptionResult(byte[] ciphertext, byte[] nonce, byte[] mac) {
            this.ciphertext = ciphertext;
            this.nonce = nonce;
            this.mac = mac;
        }

        public byte[] getCiphertext() {
            return ciphertext;
        }

        public byte[] getNonce() {
            return nonce;
        }

        public byte[] getMac() {
            return mac;
        }
    }
}