package com.datdevops.pgp.entity;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "audit_logs")
public class AuditLog {
    @Id
    private String id;

    private String correlationId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    private String action;
    private String senderId;
    private String recipientId;
    private String payloadType;

    @Column(length = 4000)
    private String details;

    private boolean success;
    private Instant timestamp;
    private String ipAddress;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "partner_id")
    private Partner partner;

    public AuditLog() {
        this.id = UUID.randomUUID().toString();
        this.timestamp = Instant.now();
    }

    public AuditLog(String userId, String action, String details, String ipAddress) {
        this();
        this.user = new User();
        this.user.setId(userId);
        this.action = action;
        this.details = details;
        this.ipAddress = ipAddress;
    }

    // Getters and Setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getCorrelationId() { return correlationId; }
    public void setCorrelationId(String correlationId) { this.correlationId = correlationId; }
    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }
    public String getSenderId() { return senderId; }
    public void setSenderId(String senderId) { this.senderId = senderId; }
    public String getRecipientId() { return recipientId; }
    public void setRecipientId(String recipientId) { this.recipientId = recipientId; }
    public String getPayloadType() { return payloadType; }
    public void setPayloadType(String payloadType) { this.payloadType = payloadType; }
    public String getDetails() { return details; }
    public void setDetails(String details) { this.details = details; }
    public boolean isSuccess() { return success; }
    public void setSuccess(boolean success) { this.success = success; }
    public Instant getTimestamp() { return timestamp; }
    public void setTimestamp(Instant timestamp) { this.timestamp = timestamp; }
    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }
    public Partner getPartner() { return partner; }
    public void setPartner(Partner partner) { this.partner = partner; }
}