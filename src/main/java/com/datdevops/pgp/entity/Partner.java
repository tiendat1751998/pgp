package com.datdevops.pgp.entity;

import jakarta.persistence.*;
import com.datdevops.pgp.listener.EntityEncryptionListener;
import com.datdevops.pgp.listener.Encrypted;
import java.time.Instant;

/**
 * Partner entity. Represents an external system (bank/fintech) connected via mTLS.
 * Relationships to KeyVersion/AuditLog/EnvelopeLog are done via ownerId/senderId strings,
 * not JPA associations, since this is M2M with no user model.
 */
@Entity
@EntityListeners(EntityEncryptionListener.class)
public class Partner {

    @Id
    private String id;

    private String name;

    @Column(length = 2048)
    private String customerRsaPublicKey;

    @Column(length = 1024)
    private String customerEd25519PublicKey;

    @Column(length = 2048)
    private String systemRsaPublicKey;

    @Column(length = 1024)
    private String systemEd25519PublicKey;

    private String keyFingerprint;

    @Column(length = 1024)
    @Encrypted
    private String keystorePassword;

    @Column(length = 2048)
    @Encrypted
    private String adminEncryptedKeystorePassword;

    private Instant createdAt;
    private Instant updatedAt;

    public Partner() {}

    @PrePersist
    protected void onCreate() {
        createdAt = Instant.now();
        updatedAt = Instant.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = Instant.now();
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getCustomerRsaPublicKey() { return customerRsaPublicKey; }
    public void setCustomerRsaPublicKey(String customerRsaPublicKey) { this.customerRsaPublicKey = customerRsaPublicKey; }
    public String getCustomerEd25519PublicKey() { return customerEd25519PublicKey; }
    public void setCustomerEd25519PublicKey(String customerEd25519PublicKey) { this.customerEd25519PublicKey = customerEd25519PublicKey; }
    public String getSystemRsaPublicKey() { return systemRsaPublicKey; }
    public void setSystemRsaPublicKey(String systemRsaPublicKey) { this.systemRsaPublicKey = systemRsaPublicKey; }
    public String getSystemEd25519PublicKey() { return systemEd25519PublicKey; }
    public void setSystemEd25519PublicKey(String systemEd25519PublicKey) { this.systemEd25519PublicKey = systemEd25519PublicKey; }
    public String getKeyFingerprint() { return keyFingerprint; }
    public void setKeyFingerprint(String keyFingerprint) { this.keyFingerprint = keyFingerprint; }
    public String getKeystorePassword() { return keystorePassword; }
    public void setKeystorePassword(String keystorePassword) { this.keystorePassword = keystorePassword; }
    public String getAdminEncryptedKeystorePassword() { return adminEncryptedKeystorePassword; }
    public void setAdminEncryptedKeystorePassword(String adminEncryptedKeystorePassword) { this.adminEncryptedKeystorePassword = adminEncryptedKeystorePassword; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}