package com.datdevops.pgp.service;

import com.datdevops.pgp.dto.request.DecryptRequest;
import com.datdevops.pgp.dto.request.EncryptRequest;
import com.datdevops.pgp.dto.response.DecryptResponse;
import com.datdevops.pgp.dto.response.EncryptResponse;
import com.datdevops.pgp.mapper.EntityMapper;
import com.datdevops.pgp.model.SecureEnvelope;
import com.datdevops.pgp.security.SenderContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;

/**
 * Orchestrator service for all cryptographic operations.
 * Enforces identity derivation and coordinates between KeyService and Crypto Engines.
 */
@Service
public class CryptoApplicationService {
    private static final Logger log = LoggerFactory.getLogger(CryptoApplicationService.class);

    private final SecureEnvelopeService envelopeService;
    private final KeyService keyService;
    private final AuditService auditService;
    private final EntityMapper entityMapper;
    private final ObjectMapper objectMapper;

    public CryptoApplicationService(SecureEnvelopeService envelopeService, 
                                    KeyService keyService, 
                                    AuditService auditService, 
                                    EntityMapper entityMapper) {
        this.envelopeService = envelopeService;
        this.keyService = keyService;
        this.auditService = auditService;
        this.entityMapper = entityMapper;
        this.objectMapper = new ObjectMapper();
    }

    public EncryptResponse encrypt(EncryptRequest request) throws Exception {
        String senderId = SenderContext.getSenderId();
        if (senderId == null) {
            throw new SecurityException("Unauthorized: No authenticated sender identity");
        }

        log.info("[CRYPTO_OP] Encrypt: sender={} recipient={}", senderId, request.recipientId());

        // 1. Resolve Keys (Cached & Ownership Verified)
        Ed25519PrivateKeyParameters signingKey = keyService.getSenderSigningKey(senderId);
        RSAKeyParameters recipientPubKey = keyService.getRecipientPublicKey(request.recipientId());

        // 2. Execute Crypto Strategy
        byte[] payloadBytes = request.payload().getBytes(StandardCharsets.UTF_8);
        String envelopeJson = envelopeService.encryptPayloadDirect(
                payloadBytes,
                request.payloadType(),
                senderId,
                request.senderKeyFingerprint(),
                request.recipientId(),
                request.recipientKeyFingerprint(),
                signingKey,
                recipientPubKey
        );

        // 3. Prepare Response
        SecureEnvelope envelope = objectMapper.readValue(envelopeJson, SecureEnvelope.class);
        String encryptedEnvelopeBase64 = entityMapper.toBase64(envelopeJson);
        EncryptResponse response = entityMapper.toEncryptResponse(envelope, encryptedEnvelopeBase64);

        // 4. Audit
        auditService.logEncrypt(envelope.getCorrelationId(), senderId, request.recipientId(), request.payloadType(), true);

        return response;
    }

    public DecryptResponse decrypt(DecryptRequest request) throws Exception {
        // 1. Parse Envelope to get identity
        String envelopeJson = new String(entityMapper.fromBase64(request.envelope()), StandardCharsets.UTF_8);
        SecureEnvelope envelope = objectMapper.readValue(envelopeJson, SecureEnvelope.class);
        
        String recipientId = envelope.getRecipient().getId();
        String senderId = envelope.getSender().getId();

        log.info("[CRYPTO_OP] Decrypt: sender={} recipient={}", senderId, recipientId);

        // 2. Resolve Keys (Cached & Ownership Verified)
        // Note: keyService.getOurDecryptionKey checks that SenderContext.getSenderId() == recipientId
        RSAKeyParameters decryptionKey = keyService.getOurDecryptionKey(recipientId);
        Ed25519PublicKeyParameters verificationKey = keyService.getSenderVerificationKey(senderId);

        // 3. Execute Crypto Strategy
        byte[] decryptedPayload = envelopeService.decryptPayloadDirect(
                envelopeJson,
                decryptionKey,
                verificationKey
        );

        String payload = new String(decryptedPayload, StandardCharsets.UTF_8);

        // 4. Audit
        auditService.logDecrypt(envelope.getCorrelationId(), senderId, recipientId, envelope.getMessageType(), true);

        return new DecryptResponse(envelope.getMessageType(), payload);
    }
}
