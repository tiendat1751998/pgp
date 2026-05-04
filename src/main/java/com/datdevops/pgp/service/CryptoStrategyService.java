package com.datdevops.pgp.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
public class CryptoStrategyService {

    public enum CryptoType {
        PGP,
        AES_GCM,
        HYBRID
    }

    @Value("${app.crypto.default-type:PGP}")
    private String defaultCryptoType;

    @Value("${app.crypto.allowed-types:PGP}")
    private String allowedTypes;

    public CryptoType getCryptoType(String requestedType) {
        if (requestedType == null || requestedType.isBlank()) {
            return CryptoType.valueOf(defaultCryptoType);
        }

        Set<String> allowed = Set.of(allowedTypes.split(","));
        String upperRequested = requestedType.toUpperCase();

        if (!allowed.contains(upperRequested)) {
            throw new IllegalArgumentException("Crypto type not allowed: " + requestedType);
        }

        return CryptoType.valueOf(upperRequested);
    }

    public byte[] encrypt(byte[] plaintext, String cryptoType, Object... params) {
        CryptoType type = getCryptoType(cryptoType);

        return switch (type) {
            case PGP -> encryptPGP(plaintext, params);
            case AES_GCM -> encryptAESGCM(plaintext, params);
            case HYBRID -> encryptHybrid(plaintext, params);
        };
    }

    public byte[] decrypt(byte[] ciphertext, String cryptoType, Object... params) {
        CryptoType type = getCryptoType(cryptoType);

        return switch (type) {
            case PGP -> decryptPGP(ciphertext, params);
            case AES_GCM -> decryptAESGCM(ciphertext, params);
            case HYBRID -> decryptHybrid(ciphertext, params);
        };
    }

    private byte[] encryptPGP(Object... params) {
        throw new UnsupportedOperationException("Use PGPService for PGP encryption");
    }

    private byte[] encryptAESGCM(Object... params) {
        throw new UnsupportedOperationException("Use EncryptionService for AES-GCM");
    }

    private byte[] encryptHybrid(Object... params) {
        throw new UnsupportedOperationException("Use EncryptionService for hybrid encryption");
    }

    private byte[] decryptPGP(Object... params) {
        throw new UnsupportedOperationException("Use SecureEnvelopeService for PGP decryption");
    }

    private byte[] decryptAESGCM(Object... params) {
        throw new UnsupportedOperationException("Use EncryptionService for AES-GCM decryption");
    }

    private byte[] decryptHybrid(Object... params) {
        throw new UnsupportedOperationException("Use EncryptionService for hybrid decryption");
    }
}