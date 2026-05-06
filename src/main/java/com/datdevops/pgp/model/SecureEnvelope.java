package com.datdevops.pgp.model;

import java.time.Instant;
import java.util.UUID;
import java.util.Map;

/**
 * Represents the structured cryptographic envelope for M2M message exchange.
 * Contains metadata, encrypted session key, and the signature.
 */
public class SecureEnvelope {

    private String messageId;
    private String correlationId;
    private String senderId;
    private String senderKeyFingerprint;
    private String recipientId;
    private String recipientKeyFingerprint;
    private String timestamp;
    private String payloadType;
    private String encryptedSessionKey;
    private String payloadCiphertext;
    private String signature;
    private Map<String, String> extraMetadata;

    public SecureEnvelope() {
    }

    public SecureEnvelope(String messageId, String senderId, String recipientId, String payloadType) {
        this.messageId = messageId;
        this.senderId = senderId;
        this.recipientId = recipientId;
        this.payloadType = payloadType;
        this.timestamp = Instant.now().toString();
    }

    // Getters and Setters
    public String getMessageId() { return messageId; }
    public void setMessageId(String messageId) { this.messageId = messageId; }
    public String getCorrelationId() { return correlationId; }
    public void setCorrelationId(String correlationId) { this.correlationId = correlationId; }
    public String getSenderId() { return senderId; }
    public void setSenderId(String senderId) { this.senderId = senderId; }
    public String getSenderKeyFingerprint() { return senderKeyFingerprint; }
    public void setSenderKeyFingerprint(String senderKeyFingerprint) { this.senderKeyFingerprint = senderKeyFingerprint; }
    public String getRecipientId() { return recipientId; }
    public void setRecipientId(String recipientId) { this.recipientId = recipientId; }
    public String getRecipientKeyFingerprint() { return recipientKeyFingerprint; }
    public void setRecipientKeyFingerprint(String recipientKeyFingerprint) { this.recipientKeyFingerprint = recipientKeyFingerprint; }
    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }
    public String getPayloadType() { return payloadType; }
    public void setPayloadType(String payloadType) { this.payloadType = payloadType; }
    public String getEncryptedSessionKey() { return encryptedSessionKey; }
    public void setEncryptedSessionKey(String encryptedSessionKey) { this.encryptedSessionKey = encryptedSessionKey; }
    public String getPayloadCiphertext() { return payloadCiphertext; }
    public void setPayloadCiphertext(String payloadCiphertext) { this.payloadCiphertext = payloadCiphertext; }
    public String getSignature() { return signature; }
    public void setSignature(String signature) { this.signature = signature; }
    public Map<String, String> getExtraMetadata() { return extraMetadata; }
    public void setExtraMetadata(Map<String, String> extraMetadata) { this.extraMetadata = extraMetadata; }

    public static class Builder {
        private final SecureEnvelope envelope = new SecureEnvelope();

        public Builder messageId(String id) { envelope.messageId = id; return this; }
        public Builder correlationId(String id) { envelope.correlationId = id; return this; }
        public Builder senderId(String id) { envelope.senderId = id; return this; }
        public Builder recipientId(String id) { envelope.recipientId = id; return this; }
        public Builder payloadType(String type) { envelope.payloadType = type; return this; }
        public Builder encryptedSessionKey(String key) { envelope.encryptedSessionKey = key; return this; }
        public Builder payloadCiphertext(String text) { envelope.payloadCiphertext = text; return this; }
        public Builder signature(String sig) { envelope.signature = sig; return this; }
        public Builder senderKeyFingerprint(String f) { envelope.senderKeyFingerprint = f; return this; }
        public Builder recipientKeyFingerprint(String f) { envelope.recipientKeyFingerprint = f; return this; }
        
        public SecureEnvelope build() {
            if (envelope.timestamp == null) {
                envelope.timestamp = Instant.now().toString();
            }
            if (envelope.messageId == null) {
                envelope.messageId = UUID.randomUUID().toString();
            }
            return envelope;
        }
    }
    
    public Sender getSender() {
        return new Sender(senderId, senderKeyFingerprint);
    }
    
    public Recipient getRecipient() {
        return new Recipient(recipientId, recipientKeyFingerprint);
    }
    
    public static record Sender(String id, String keyFingerprint) {}
    public static record Recipient(String id, String keyFingerprint) {}
}