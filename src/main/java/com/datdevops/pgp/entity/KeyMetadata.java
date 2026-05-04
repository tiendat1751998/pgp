package com.datdevops.pgp.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "key_metadata")
public class KeyMetadata {

    @Id
    private String id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "partner_id", nullable = false, unique = true)
    private Partner partner;

    private String currentKeyVersion;
    private String previousKeyVersion;
    private Instant lastRotatedAt;
    private String rotationPolicy;
    private int rotationIntervalDays;
    private Instant nextRotationDue;
    private int maxKeyVersions;
    private String keyAlgorithm;
    private int keySize;
    private Instant createdAt;
    private Instant updatedAt;

    public KeyMetadata() {
        this.createdAt = Instant.now();
        this.updatedAt = Instant.now();
        this.rotationIntervalDays = 90;
        this.maxKeyVersions = 5;
    }

    public KeyMetadata(Partner partner) {
        this();
        this.partner = partner;
        this.id = partner.getId() + "-metadata";
    }

    @PrePersist
    protected void onCreate() {
        createdAt = Instant.now();
        updatedAt = Instant.now();
        if (id == null) id = partner.getId() + "-metadata";
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = Instant.now();
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public Partner getPartner() { return partner; }
    public void setPartner(Partner partner) { this.partner = partner; }
    public String getCurrentKeyVersion() { return currentKeyVersion; }
    public void setCurrentKeyVersion(String currentKeyVersion) { this.currentKeyVersion = currentKeyVersion; }
    public String getPreviousKeyVersion() { return previousKeyVersion; }
    public void setPreviousKeyVersion(String previousKeyVersion) { this.previousKeyVersion = previousKeyVersion; }
    public Instant getLastRotatedAt() { return lastRotatedAt; }
    public void setLastRotatedAt(Instant lastRotatedAt) { this.lastRotatedAt = lastRotatedAt; }
    public String getRotationPolicy() { return rotationPolicy; }
    public void setRotationPolicy(String rotationPolicy) { this.rotationPolicy = rotationPolicy; }
    public int getRotationIntervalDays() { return rotationIntervalDays; }
    public void setRotationIntervalDays(int rotationIntervalDays) { this.rotationIntervalDays = rotationIntervalDays; }
    public Instant getNextRotationDue() { return nextRotationDue; }
    public void setNextRotationDue(Instant nextRotationDue) { this.nextRotationDue = nextRotationDue; }
    public int getMaxKeyVersions() { return maxKeyVersions; }
    public void setMaxKeyVersions(int maxKeyVersions) { this.maxKeyVersions = maxKeyVersions; }
    public String getKeyAlgorithm() { return keyAlgorithm; }
    public void setKeyAlgorithm(String keyAlgorithm) { this.keyAlgorithm = keyAlgorithm; }
    public int getKeySize() { return keySize; }
    public void setKeySize(int keySize) { this.keySize = keySize; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}