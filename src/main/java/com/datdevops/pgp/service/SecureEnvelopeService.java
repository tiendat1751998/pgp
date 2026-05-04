package com.datdevops.pgp.service;

import com.datdevops.pgp.model.SecureEnvelope;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.resilience4j.bulkhead.annotation.Bulkhead;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.retry.annotation.Retry;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
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
    private final ReplayProtectionService replayProtectionService;
    private final ObjectMapper objectMapper;
    private final SecureRandom secureRandom;

    @Autowired
    public SecureEnvelopeService(
            EncryptionService encryptionService,
            SigningService signingService,
            SignatureVerificationService signatureVerificationService,
            ReplayProtectionService replayProtectionService,
            ObjectMapper objectMapper) {
        this.encryptionService = encryptionService;
        this.signingService = signingService;
        this.signatureVerificationService = signatureVerificationService;
        this.replayProtectionService = replayProtectionService;
        this.objectMapper = objectMapper;
        this.secureRandom = new SecureRandom();
    }

    @CircuitBreaker(name = CIRCUIT_BREAKER)
    @Bulkhead(name = BULKHEAD)
    public String encryptPayloadDirect(
            byte[] payload,
            String messageType,
            String senderId,
            String senderKeyFingerprint,
            String recipientId,
            String recipientKeyFingerprint,
            Ed25519PrivateKeyParameters signingKey,
            RSAKeyParameters recipientRSAPublicKey) throws Exception {

        String payloadHash = computeHash(payload);
        final long authTimestamp = System.currentTimeMillis();
        final String correlationId = UUID.randomUUID().toString();

        String dataToSign = payloadHash + "|" + senderId + "|" + recipientId + "|" + authTimestamp;
        byte[] authSignature = signingService.sign(dataToSign.getBytes(StandardCharsets.UTF_8), signingKey);

        byte[] sessionKey = generateSessionKey();
        byte[] encryptedSessionKey = encryptionService.encryptSessionKey(sessionKey, recipientRSAPublicKey);
        String encryptedSessionKeyBase64 = Base64.getEncoder().encodeToString(encryptedSessionKey);

        String authData = senderId + "|" + recipientId + "|" + authTimestamp;
        EncryptionService.EncryptionResult encryptResult = encryptionService.encrypt(
                payload, sessionKey, authData.getBytes(StandardCharsets.UTF_8));

        byte[] combined = new byte[encryptResult.getCiphertext().length + encryptResult.getNonce().length + encryptResult.getMac().length];
        System.arraycopy(encryptResult.getCiphertext(), 0, combined, 0, encryptResult.getCiphertext().length);
        System.arraycopy(encryptResult.getNonce(), 0, combined, encryptResult.getCiphertext().length, encryptResult.getNonce().length);
        System.arraycopy(encryptResult.getMac(), 0, combined, encryptResult.getCiphertext().length + encryptResult.getNonce().length, encryptResult.getMac().length);

        String encryptedPayload = Base64.getEncoder().encodeToString(combined);

        SecureEnvelope envelope = SecureEnvelope.builder()
                .messageType(messageType)
                .sender(senderId, senderKeyFingerprint)
                .recipient(recipientId, recipientKeyFingerprint)
                .build();

        envelope.setEncryptedPayload(encryptedPayload);
        envelope.setEncryptedSessionKey(encryptedSessionKeyBase64);
        envelope.setSignature(Base64.getEncoder().encodeToString(authSignature));
        envelope.setCorrelationId(correlationId);
        envelope.setAuthTimestamp(authTimestamp);

        return objectMapper.writeValueAsString(envelope);
    }

    @CircuitBreaker(name = CIRCUIT_BREAKER)
    @Bulkhead(name = BULKHEAD)
    public byte[] decryptPayloadDirect(
            String envelopeJson,
            RSAKeyParameters recipientRSAPrivateKey,
            Ed25519PublicKeyParameters senderPublicKey) throws Exception {

        SecureEnvelope envelope = objectMapper.readValue(envelopeJson, SecureEnvelope.class);

        if (envelope.getSignature() == null || envelope.getSignature().isEmpty()) {
            throw new SecurityException("Missing signature in envelope");
        }

        long authTimestamp = envelope.getAuthTimestamp();
        if (!replayProtectionService.validateTimestamp(authTimestamp, 300)) {
            throw new SecurityException("Message expired or timestamp out of allowable window (±5min)");
        }

        String recipientId = envelope.getRecipient() != null ? envelope.getRecipient().getId() : "UNKNOWN";
        if (!replayProtectionService.isValidNonce(envelope.getCorrelationId(), recipientId)) {
            throw new SecurityException("Replay attack detected: message already processed");
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

            String authData = envelope.getSender().getId() + "|" + envelope.getRecipient().getId() + "|" + authTimestamp;

            byte[] decryptedPayload = encryptionService.decrypt(
                    ciphertext, sessionKey, nonce, mac, authData.getBytes(StandardCharsets.UTF_8));

            String storedHash = computeHash(decryptedPayload);
            String dataToVerify = storedHash + "|" + envelope.getSender().getId() + "|" +
                    envelope.getRecipient().getId() + "|" + authTimestamp;

            byte[] signatureBytes = Base64.getDecoder().decode(envelope.getSignature());
            boolean signatureValid = signatureVerificationService.verify(
                    dataToVerify.getBytes(StandardCharsets.UTF_8), signatureBytes, senderPublicKey);

            if (!signatureValid) {
                throw new SecurityException("Invalid signature - message may have been tampered with");
            }

            return decryptedPayload;
        } finally {
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
}
