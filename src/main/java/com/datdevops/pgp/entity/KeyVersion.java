package com.datdevops.pgp.entity;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "key_versions")
public class KeyVersion {

    @Id
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "partner_id", nullable = false)
    private Partner partner;

    private String keyType;
    private String keyVersion;
    private Instant createdAt;
    private Instant expiresAt;
    private boolean active;
    private String fingerprint;
    private String publicKeyData;
    private String encryptedPrivateKey;
    private boolean deprecated;

    public KeyVersion() {
        this.createdAt = Instant.now();
        this.active = true;
        this.deprecated = false;
    }

    public KeyVersion(Partner partner, String keyType, String keyVersion) {
        this();
        this.partner = partner;
        this.keyType = keyType;
        this.keyVersion = keyVersion;
        this.id = partner.getId() + "-" + keyType + "-" + keyVersion;
    }

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) createdAt = Instant.now();
        if (id == null) id = partner.getId() + "-" + keyType + "-" + keyVersion;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public Partner getPartner() { return partner; }
    public void setPartner(Partner partner) { this.partner = partner; }
    public String getKeyType() { return keyType; }
    public void setKeyType(String keyType) { this.keyType = keyType; }
    public String getKeyVersion() { return keyVersion; }
    public void setKeyVersion(String keyVersion) { this.keyVersion = keyVersion; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }
    public String getFingerprint() { return fingerprint; }
    public void setFingerprint(String fingerprint) { this.fingerprint = fingerprint; }
    public String getPublicKeyData() { return publicKeyData; }
    public void setPublicKeyData(String publicKeyData) { this.publicKeyData = publicKeyData; }
    public String getEncryptedPrivateKey() { return encryptedPrivateKey; }
    public void setEncryptedPrivateKey(String encryptedPrivateKey) { this.encryptedPrivateKey = encryptedPrivateKey; }
    public boolean isDeprecated() { return deprecated; }
    public void setDeprecated(boolean deprecated) { this.deprecated = deprecated; }
}