package com.datdevops.pgp.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "envelope_logs")
public class EnvelopeLog {

    @Id
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "partner_id")
    private Partner partner;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    private String envelopeType;
    private String status;
    private String messageType;
    private String mti;
    private String processingCode;
    private String transactionId;
    private String correlationId;
    private String nonce;
    private Long processingTimeMs;
    private String keyVersionUsed;
    private String algorithm;
    private String errorMessage;
    private Instant createdAt;

    public EnvelopeLog() {
        this.id = java.util.UUID.randomUUID().toString();
        this.createdAt = Instant.now();
    }

    public EnvelopeLog(Partner partner, String envelopeType, String status) {
        this();
        this.partner = partner;
        this.envelopeType = envelopeType;
        this.status = status;
    }

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) createdAt = Instant.now();
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public Partner getPartner() { return partner; }
    public void setPartner(Partner partner) { this.partner = partner; }
    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }
    public String getEnvelopeType() { return envelopeType; }
    public void setEnvelopeType(String envelopeType) { this.envelopeType = envelopeType; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public String getMessageType() { return messageType; }
    public void setMessageType(String messageType) { this.messageType = messageType; }
    public String getMti() { return mti; }
    public void setMti(String mti) { this.mti = mti; }
    public String getProcessingCode() { return processingCode; }
    public void setProcessingCode(String processingCode) { this.processingCode = processingCode; }
    public String getTransactionId() { return transactionId; }
    public void setTransactionId(String transactionId) { this.transactionId = transactionId; }
    public String getCorrelationId() { return correlationId; }
    public void setCorrelationId(String correlationId) { this.correlationId = correlationId; }
    public String getNonce() { return nonce; }
    public void setNonce(String nonce) { this.nonce = nonce; }
    public Long getProcessingTimeMs() { return processingTimeMs; }
    public void setProcessingTimeMs(Long processingTimeMs) { this.processingTimeMs = processingTimeMs; }
    public String getKeyVersionUsed() { return keyVersionUsed; }
    public void setKeyVersionUsed(String keyVersionUsed) { this.keyVersionUsed = keyVersionUsed; }
    public String getAlgorithm() { return algorithm; }
    public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }
    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}