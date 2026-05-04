package com.datdevops.pgp.service;

import com.datdevops.pgp.model.SecureEnvelope;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.resilience4j.bulkhead.annotation.Bulkhead;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.retry.annotation.Retry;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

@Service
public class SecureEnvelopeService {

    private static final String CIRCUIT_BREAKER = "secureEnvelope";
    private static final String BULKHEAD = "secureEnvelope";
    private static final String RETRY = "keyOperation";

    private final EncryptionService encryptionService;
    private final SigningService signingService;
    private final SignatureVerificationService signatureVerificationService;
    private final KeyPairGeneratorService keyPairGeneratorService;
    private final RSAKeyPairGeneratorService rsaKeyPairGeneratorService;
    private final ReplayProtectionService replayProtectionService;
    private final KeyRotationService keyRotationService;
    private final ObjectMapper objectMapper;
    private final SecureRandom secureRandom;

    @Autowired
    public SecureEnvelopeService(
            EncryptionService encryptionService,
            SigningService signingService,
            SignatureVerificationService signatureVerificationService,
            KeyPairGeneratorService keyPairGeneratorService,
            RSAKeyPairGeneratorService rsaKeyPairGeneratorService,
            ReplayProtectionService replayProtectionService,
            KeyRotationService keyRotationService,
            ObjectMapper objectMapper) {
        this.encryptionService = encryptionService;
        this.signingService = signingService;
        this.signatureVerificationService = signatureVerificationService;
        this.keyPairGeneratorService = keyPairGeneratorService;
        this.rsaKeyPairGeneratorService = rsaKeyPairGeneratorService;
        this.replayProtectionService = replayProtectionService;
        this.keyRotationService = keyRotationService;
        this.objectMapper = objectMapper;
        this.secureRandom = new SecureRandom();
    }

    public SecureEnvelopeService(
            EncryptionService encryptionService,
            SigningService signingService,
            SignatureVerificationService signatureVerificationService,
            KeyPairGeneratorService keyPairGeneratorService,
            RSAKeyPairGeneratorService rsaKeyPairGeneratorService,
            ReplayProtectionService replayProtectionService,
            ObjectMapper objectMapper) {
        this(
                encryptionService,
                signingService,
                signatureVerificationService,
                keyPairGeneratorService,
                rsaKeyPairGeneratorService,
                replayProtectionService,
                new KeyRotationService(),
                objectMapper);
    }

    @CircuitBreaker(name = CIRCUIT_BREAKER, fallbackMethod = "encryptFallback")
    @Bulkhead(name = BULKHEAD)
    public String encryptPayload(
            byte[] payload,
            String messageType,
            String senderId,
            String senderKeyFingerprint,
            String recipientId,
            String recipientKeyFingerprint,
            byte[] senderPrivateKey,
            RSAKeyParameters recipientRSAPublicKey,
            byte[] sessionKey) throws Exception {

        String payloadHash = computeHash(payload);

        final long authTimestamp = System.currentTimeMillis();
        final String correlationId = UUID.randomUUID().toString();

        String dataToSign = payloadHash + "|" + senderId + "|" + recipientId + "|" + authTimestamp;
        byte[] authSignature = signingService.sign(
                dataToSign.getBytes(StandardCharsets.UTF_8),
                new org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters(senderPrivateKey, 0));

        byte[] sessionKeyForEncrypt = sessionKey != null ? sessionKey : generateSessionKey();

        byte[] encryptedSessionKey = encryptionService.encryptSessionKey(sessionKeyForEncrypt, recipientRSAPublicKey);
        String encryptedSessionKeyBase64 = Base64.getEncoder().encodeToString(encryptedSessionKey);

        String authData = senderId + "|" + recipientId + "|" + authTimestamp;

        EncryptionService.EncryptionResult encryptResult = encryptionService.encrypt(
                payload,
                sessionKeyForEncrypt,
                authData.getBytes(StandardCharsets.UTF_8));

        byte[] combined = new byte[encryptResult.getCiphertext().length + encryptResult.getNonce().length
                + encryptResult.getMac().length];
        System.arraycopy(encryptResult.getCiphertext(), 0, combined, 0, encryptResult.getCiphertext().length);
        System.arraycopy(encryptResult.getNonce(), 0, combined, encryptResult.getCiphertext().length,
                encryptResult.getNonce().length);
        System.arraycopy(encryptResult.getMac(), 0, combined,
                encryptResult.getCiphertext().length + encryptResult.getNonce().length, encryptResult.getMac().length);

        String encryptedPayload = Base64.getEncoder().encodeToString(combined);

        SecureEnvelope envelope = SecureEnvelope.builder()
                .messageType(messageType)
                .sender(senderId, senderKeyFingerprint)
                .recipient(recipientId, recipientKeyFingerprint)
                .build();

        envelope.setEncryptedPayload(encryptedPayload);
        envelope.setEncryptedSessionKey(encryptedSessionKeyBase64);
        envelope.setSignature(Base64.getEncoder().encodeToString(authSignature));
        // \u2705 correlationId = UUID (unpredictable), authTimestamp stored separately
        // for replay validation
        envelope.setCorrelationId(correlationId);
        envelope.setAuthTimestamp(authTimestamp);

        return objectMapper.writeValueAsString(envelope);
    }

    @CircuitBreaker(name = CIRCUIT_BREAKER, fallbackMethod = "encryptPayloadWithKeyPairFallback")
    @Bulkhead(name = BULKHEAD)
    @Retry(name = RETRY)
    public String encryptPayloadWithKeyPair(
            byte[] payload,
            String messageType,
            String senderId,
            String senderKeyFingerprint,
            String recipientId,
            String recipientKeyFingerprint,
            byte[] senderPrivateKey,
            RSAKeyParameters recipientRSAPublicKey) throws Exception {

        return encryptPayload(payload, messageType, senderId, senderKeyFingerprint, recipientId,
                recipientKeyFingerprint,
                senderPrivateKey, recipientRSAPublicKey, null);
    }

    @CircuitBreaker(name = CIRCUIT_BREAKER, fallbackMethod = "decryptFallback")
    @Bulkhead(name = BULKHEAD)
    @Retry(name = RETRY)
    public byte[] decryptPayload(
            String envelopeJson,
            RSAKeyParameters recipientRSAPrivateKey,
            byte[] senderPublicKey) throws Exception {

        SecureEnvelope envelope = objectMapper.readValue(envelopeJson, SecureEnvelope.class);

        if (envelope.getSignature() == null || envelope.getSignature().isEmpty()) {
            throw new SecurityException("Missing signature in envelope");
        }

        // ✅ STEP 1 — Validate timestamp from dedicated authTimestamp field (±5 minutes)
        long authTimestamp = envelope.getAuthTimestamp();
        if (authTimestamp == 0) {
            throw new SecurityException("Missing authTimestamp in envelope");
        }
        if (!replayProtectionService.validateTimestamp(authTimestamp, 300)) {
            throw new SecurityException("Message expired or timestamp out of allowable window (±5min)");
        }

        // ✅ STEP 2 — Replay nonce check (correlationId UUID must be unique per
        // recipient)
        String recipientId = envelope.getRecipient() != null ? envelope.getRecipient().getId() : "UNKNOWN";
        if (!replayProtectionService.isValidNonce(envelope.getCorrelationId(), recipientId)) {
            throw new SecurityException("Replay attack detected: message already processed");
        }

        // ✅ STEP 3 — Validate key version if specified in envelope
        String keyVersion = envelope.getRecipient() != null ? envelope.getRecipient().getKeyVersion() : null;
        if (keyVersion != null && !keyVersion.isEmpty()) {
            try {
                keyRotationService.getKeyVersionById(recipientId + "-RSA-" + keyVersion);
            } catch (SecurityException e) {
                throw new SecurityException("Invalid or inactive key version: " + keyVersion);
            }
        }

        byte[] encryptedSessionKey = Base64.getDecoder().decode(envelope.getEncryptedSessionKey());
        byte[] sessionKey = encryptionService.decryptSessionKey(encryptedSessionKey, recipientRSAPrivateKey);

        try {
            byte[] combined = Base64.getDecoder().decode(envelope.getEncryptedPayload());

            byte[] nonce = new byte[12];
            byte[] mac = new byte[16];
            byte[] ciphertext = new byte[combined.length - 12 - 16];

            System.arraycopy(combined, 0, ciphertext, 0, ciphertext.length);
            System.arraycopy(combined, ciphertext.length, nonce, 0, 12);
            System.arraycopy(combined, ciphertext.length + 12, mac, 0, 16);

            String authData = envelope.getSender().getId() + "|" + envelope.getRecipient().getId() + "|" +
                    authTimestamp;

            byte[] decryptedPayload = encryptionService.decrypt(
                    ciphertext,
                    sessionKey,
                    nonce,
                    mac,
                    authData.getBytes(StandardCharsets.UTF_8));

            String storedHash = computeHash(decryptedPayload);

            String dataToVerify = storedHash + "|" + envelope.getSender().getId() + "|" +
                    envelope.getRecipient().getId() + "|" + authTimestamp;

            byte[] signatureBytes = Base64.getDecoder().decode(envelope.getSignature());
            boolean signatureValid = signatureVerificationService.verify(
                    dataToVerify.getBytes(StandardCharsets.UTF_8),
                    signatureBytes,
                    new org.bouncycastle.crypto.params.Ed25519PublicKeyParameters(senderPublicKey, 0));

            if (!signatureValid) {
                throw new SecurityException("Invalid signature - message may have been tampered with");
            }

            return decryptedPayload;
        } finally {
            // ✅ STEP 3 — Zero-out session key immediately after use
            java.util.Arrays.fill(sessionKey, (byte) 0);
        }
    }

    private byte[] generateSessionKey() {
        byte[] key = new byte[32];
        secureRandom.nextBytes(key);
        return key;
    }

    private String computeHash(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute hash", e);
        }
    }

    // Fallback methods for Circuit Breaker
    @SuppressWarnings("unused")
    private String encryptFallback(byte[] payload, String messageType, String senderId,
            String senderKeyFingerprint, String recipientId, String recipientKeyFingerprint,
            byte[] senderPrivateKey, RSAKeyParameters recipientRSAPublicKey,
            byte[] sessionKey, Throwable t) {
        throw new RuntimeException("Encryption service unavailable. Please retry later. Cause: " + t.getMessage());
    }

    @SuppressWarnings("unused")
    private byte[] decryptFallback(String envelopeJson, RSAKeyParameters recipientRSAPrivateKey,
            byte[] senderPublicKey, Throwable t) {
        throw new RuntimeException("Decryption service unavailable. Please retry later. Cause: " + t.getMessage());
    }

    @SuppressWarnings("unused")
    private String encryptPayloadWithKeyPairFallback(byte[] payload, String messageType, String senderId,
            String senderKeyFingerprint, String recipientId,
            String recipientKeyFingerprint, byte[] senderPrivateKey,
            RSAKeyParameters recipientRSAPublicKey, Throwable t) {
        throw new RuntimeException("Encryption service unavailable. Please retry later. Cause: " + t.getMessage());
    }
}
