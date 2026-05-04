package com.datdevops.pgp.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "partner_managers")
public class PartnerManager {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "partner_id", nullable = false)
    private Partner partner;

    private String role;
    private Instant assignedAt;
    private Instant revokedAt;
    private boolean active;

    public PartnerManager() {
        this.assignedAt = Instant.now();
        this.active = true;
    }

    public PartnerManager(User user, Partner partner, String role) {
        this();
        this.user = user;
        this.partner = partner;
        this.role = role;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }
    public Partner getPartner() { return partner; }
    public void setPartner(Partner partner) { this.partner = partner; }
    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
    public Instant getAssignedAt() { return assignedAt; }
    public void setAssignedAt(Instant assignedAt) { this.assignedAt = assignedAt; }
    public Instant getRevokedAt() { return revokedAt; }
    public void setRevokedAt(Instant revokedAt) { this.revokedAt = revokedAt; }
    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }
}