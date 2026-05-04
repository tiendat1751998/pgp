package com.datdevops.pgp.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "key_version_info")
public class KeyVersionInfo {

    @Id
    private String keyId;

    @Column(nullable = false)
    private String entityId;

    @Column(nullable = false)
    private String keyType;

    private String version;

    @Column(length = 4000)
    private String rsaPublicKey;

    @Column(length = 1024)
    private String ed25519PublicKey;

    private Instant createdAt;

    private Instant expiresAt;

    @Column(nullable = false)
    private boolean active;

    private boolean deprecated;

    public KeyVersionInfo() {
        this.createdAt = Instant.now();
        this.active = true;
        this.deprecated = false;
    }

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) createdAt = Instant.now();
    }

    public String getKeyId() { return keyId; }
    public void setKeyId(String keyId) { this.keyId = keyId; }
    public String getEntityId() { return entityId; }
    public void setEntityId(String entityId) { this.entityId = entityId; }
    public String getKeyType() { return keyType; }
    public void setKeyType(String keyType) { this.keyType = keyType; }
    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }
    public String getRsaPublicKey() { return rsaPublicKey; }
    public void setRsaPublicKey(String rsaPublicKey) { this.rsaPublicKey = rsaPublicKey; }
    public String getEd25519PublicKey() { return ed25519PublicKey; }
    public void setEd25519PublicKey(String ed25519PublicKey) { this.ed25519PublicKey = ed25519PublicKey; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }
    public boolean isDeprecated() { return deprecated; }
    public void setDeprecated(boolean deprecated) { this.deprecated = deprecated; }
}