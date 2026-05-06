package com.datdevops.pgp.service;

import com.datdevops.pgp.model.SecureEnvelope;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.resilience4j.bulkhead.annotation.Bulkhead;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.retry.annotation.Retry;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

@Service
public class SecureEnvelopeService {

    private static final Logger log = LoggerFactory.getLogger(SecureEnvelopeService.class);

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
            String payloadType,
            String senderId,
            String senderKeyFingerprint,
            String recipientId,
            String recipientKeyFingerprint,
            Ed25519PrivateKeyParameters signingKey,
            RSAKeyParameters recipientRSAPublicKey) throws Exception {

        final long authTimestampMillis = System.currentTimeMillis();
        final String authTimestamp = String.valueOf(authTimestampMillis);
        final String correlationId = UUID.randomUUID().toString();

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

        // Sign the ENCRYPTED payload and metadata (Encrypt-then-Sign)
        String dataToSign = encryptedPayload + "|" + senderId + "|" + recipientId + "|" + authTimestamp;
        byte[] authSignature = signingService.sign(dataToSign.getBytes(StandardCharsets.UTF_8), signingKey);

        SecureEnvelope envelope = new SecureEnvelope.Builder()
                .payloadType(payloadType)
                .senderId(senderId)
                .senderKeyFingerprint(senderKeyFingerprint)
                .recipientId(recipientId)
                .recipientKeyFingerprint(recipientKeyFingerprint)
                .payloadCiphertext(encryptedPayload)
                .encryptedSessionKey(encryptedSessionKeyBase64)
                .signature(Base64.getEncoder().encodeToString(authSignature))
                .correlationId(correlationId)
                .build();

        // Note: Builder already sets timestamp to Instant.now().toString() if not set.
        // We override it with our explicit authTimestamp to ensure consistency in signature.
        envelope.setTimestamp(authTimestamp);

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

        String authTimestamp = envelope.getTimestamp();
        if (!replayProtectionService.validateTimestamp(Long.parseLong(authTimestamp), 300)) {
            throw new SecurityException("Message expired or timestamp out of allowable window (±5min)");
        }

        // 1. Authenticate FIRST (Encrypt-then-Sign)
        // This prevents DoS and Oracle attacks by rejecting tampered envelopes before decryption.
        String dataToVerify = envelope.getPayloadCiphertext() + "|" + envelope.getSender().id() + "|" +
                envelope.getRecipient().id() + "|" + authTimestamp;

        byte[] signatureBytes = Base64.getDecoder().decode(envelope.getSignature());
        boolean signatureValid = signatureVerificationService.verify(
                dataToVerify.getBytes(StandardCharsets.UTF_8), signatureBytes, senderPublicKey);

        if (!signatureValid) {
            log.error("[SECURITY_EVENT] Invalid signature for correlationId: {}", envelope.getCorrelationId());
            throw new SecurityException("Invalid signature - message may have been tampered with or sender is spoofed");
        }

        // 2. Resolve Session Key
        byte[] encryptedSessionKey = Base64.getDecoder().decode(envelope.getEncryptedSessionKey());
        byte[] sessionKey = encryptionService.decryptSessionKey(encryptedSessionKey, recipientRSAPrivateKey);

        try {
            // 3. Decrypt Payload (AES-GCM Authenticated Decryption)
            byte[] combined = Base64.getDecoder().decode(envelope.getPayloadCiphertext());

            int minLength = 12 + 16;
            if (combined.length < minLength) {
                throw new IllegalArgumentException("Invalid encrypted payload: too short (" + combined.length + " bytes), minimum is " + minLength);
            }

            byte[] nonce = new byte[12];
            byte[] mac = new byte[16];
            byte[] ciphertext = new byte[combined.length - 12 - 16];

            System.arraycopy(combined, 0, ciphertext, 0, ciphertext.length);
            System.arraycopy(combined, ciphertext.length, nonce, 0, 12);
            System.arraycopy(combined, ciphertext.length + 12, mac, 0, 16);

            String authData = envelope.getSender().id() + "|" + envelope.getRecipient().id() + "|" + authTimestamp;

            return encryptionService.decrypt(
                    ciphertext, sessionKey, nonce, mac, authData.getBytes(StandardCharsets.UTF_8));
        } finally {
            if (sessionKey != null) {
                Arrays.fill(sessionKey, (byte) 0);
            }
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
