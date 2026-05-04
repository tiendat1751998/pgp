package com.datdevops.pgp.model;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

public class SecureEnvelope {

    private String messageId;
    private String correlationId;
    private String messageType;
    private AlgorithmInfo algorithm;
    private SenderInfo sender;
    private RecipientInfo recipient;
    private String timestamp;
    private String nonce;
    private String encryptedSessionKey;
    private String encryptedPayload;
    private String signature;
    private String compression;
    private long authTimestamp; // Unix epoch ms — used for replay protection timestamp window

    public static class AlgorithmInfo {
        public String encryption;
        public String keyExchange;
        public String signature;
        public String hash;

        public AlgorithmInfo() {
            this.encryption = "AES-256-GCM";
            this.keyExchange = "X25519";
            this.signature = "Ed25519";
            this.hash = "SHA-256";
        }
    }

    public static class SenderInfo {
        public String id;
        public String keyFingerprint;

        public SenderInfo() {
        }

        public SenderInfo(String id, String keyFingerprint) {
            this.id = id;
            this.keyFingerprint = keyFingerprint;
        }

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getKeyFingerprint() {
            return keyFingerprint;
        }

        public void setKeyFingerprint(String keyFingerprint) {
            this.keyFingerprint = keyFingerprint;
        }
    }

    public static class RecipientInfo {
        public String id;
        public String keyFingerprint;
        public String keyVersion;

        public RecipientInfo() {
        }

        public RecipientInfo(String id, String keyFingerprint) {
            this.id = id;
            this.keyFingerprint = keyFingerprint;
        }

        public RecipientInfo(String id, String keyFingerprint, String keyVersion) {
            this.id = id;
            this.keyFingerprint = keyFingerprint;
            this.keyVersion = keyVersion;
        }

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getKeyFingerprint() {
            return keyFingerprint;
        }

        public void setKeyFingerprint(String keyFingerprint) {
            this.keyFingerprint = keyFingerprint;
        }

        public String getKeyVersion() {
            return keyVersion;
        }

        public void setKeyVersion(String keyVersion) {
            this.keyVersion = keyVersion;
        }
    }

    public SecureEnvelope() {
        this.algorithm = new AlgorithmInfo();
        this.sender = new SenderInfo();
        this.recipient = new RecipientInfo();
        this.timestamp = java.time.Instant.now().toString();
        this.compression = "NONE";
    }

    public String getMessageId() {
        return messageId;
    }

    public void setMessageId(String messageId) {
        this.messageId = messageId;
    }

    public String getCorrelationId() {
        return correlationId;
    }

    public void setCorrelationId(String correlationId) {
        this.correlationId = correlationId;
    }

    public String getMessageType() {
        return messageType;
    }

    public void setMessageType(String messageType) {
        this.messageType = messageType;
    }

    public AlgorithmInfo getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(AlgorithmInfo algorithm) {
        this.algorithm = algorithm;
    }

    public SenderInfo getSender() {
        return sender;
    }

    public void setSender(SenderInfo sender) {
        this.sender = sender;
    }

    public RecipientInfo getRecipient() {
        return recipient;
    }

    public void setRecipient(RecipientInfo recipient) {
        this.recipient = recipient;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getEncryptedSessionKey() {
        return encryptedSessionKey;
    }

    public void setEncryptedSessionKey(String encryptedSessionKey) {
        this.encryptedSessionKey = encryptedSessionKey;
    }

    public String getEncryptedPayload() {
        return encryptedPayload;
    }

    public void setEncryptedPayload(String encryptedPayload) {
        this.encryptedPayload = encryptedPayload;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getCompression() {
        return compression;
    }

    public void setCompression(String compression) {
        this.compression = compression;
    }

    public long getAuthTimestamp() {
        return authTimestamp;
    }

    public void setAuthTimestamp(long authTimestamp) {
        this.authTimestamp = authTimestamp;
    }

    public static SecureEnvelopeBuilder builder() {
        return new SecureEnvelopeBuilder();
    }

    public static class SecureEnvelopeBuilder {
        private final SecureEnvelope envelope = new SecureEnvelope();
        private final SecureRandom secureRandom = new SecureRandom();

        public SecureEnvelopeBuilder messageId(String messageId) {
            envelope.messageId = messageId;
            return this;
        }

        public SecureEnvelopeBuilder correlationId(String correlationId) {
            envelope.correlationId = correlationId;
            return this;
        }

        public SecureEnvelopeBuilder messageType(String messageType) {
            envelope.messageType = messageType;
            return this;
        }

        public SecureEnvelopeBuilder sender(String id, String keyFingerprint) {
            envelope.sender = new SenderInfo(id, keyFingerprint);
            return this;
        }

        public SecureEnvelopeBuilder recipient(String id, String keyFingerprint) {
            envelope.recipient = new RecipientInfo(id, keyFingerprint);
            return this;
        }

        public SecureEnvelopeBuilder compression(String compression) {
            envelope.compression = compression;
            return this;
        }

        public SecureEnvelope build() {
            if (envelope.messageId == null) {
                envelope.messageId = UUID.randomUUID().toString();
            }
            if (envelope.correlationId == null) {
                envelope.correlationId = UUID.randomUUID().toString();
            }
            if (envelope.timestamp == null) {
                envelope.timestamp = java.time.Instant.now().toString();
            }
            byte[] nonceBytes = new byte[16];
            secureRandom.nextBytes(nonceBytes);
            envelope.nonce = Base64.getEncoder().encodeToString(nonceBytes);
            return envelope;
        }
    }
}