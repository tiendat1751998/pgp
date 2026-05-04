package com.datdevops.pgp.entity;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "users")
public class User {
    @Id
    private String id;

    @Column(unique = true)
    private String username;

    @Column(unique = true)
    private String email;

    private String passwordHash;
    private String role;
    private boolean active;
    private Instant createdAt;
    private Instant updatedAt;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<AuditLog> auditLogs = new ArrayList<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<EnvelopeLog> envelopeLogs = new ArrayList<>();

    @ManyToMany(mappedBy = "managers")
    private List<Partner> managedPartners = new ArrayList<>();

    public User() {
        this.createdAt = Instant.now();
        this.updatedAt = Instant.now();
    }

    public User(String username, String email, String passwordHash) {
        this();
        this.username = username;
        this.email = email;
        this.passwordHash = passwordHash;
        this.active = true;
    }

    // Getters and Setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getPasswordHash() { return passwordHash; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }
    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
    public List<AuditLog> getAuditLogs() { return auditLogs; }
    public void setAuditLogs(List<AuditLog> auditLogs) { this.auditLogs = auditLogs; }
    public List<EnvelopeLog> getEnvelopeLogs() { return envelopeLogs; }
    public void setEnvelopeLogs(List<EnvelopeLog> envelopeLogs) { this.envelopeLogs = envelopeLogs; }
    public List<Partner> getManagedPartners() { return managedPartners; }
    public void setManagedPartners(List<Partner> managedPartners) { this.managedPartners = managedPartners; }
}