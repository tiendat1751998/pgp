-- ============================================================
-- PGP Crypto Gateway - Production Database Schema
-- MariaDB/MySQL Compatible
-- ============================================================

-- ============================================================
-- USERS TABLE (Optimized with ENUM for role)
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('ADMIN', 'OPERATOR', 'USER', 'AUDITOR') NOT NULL DEFAULT 'USER',
    active TINYINT(1) NOT NULL DEFAULT 1 COMMENT 'Boolean as TINYINT for performance',
    created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    CONSTRAINT uk_users_username UNIQUE (username),
    CONSTRAINT uk_users_email UNIQUE (email),
    INDEX idx_role (role),
    INDEX idx_active (active),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- PARTNERS TABLE (Encrypted columns at application level)
-- ============================================================
CREATE TABLE IF NOT EXISTS partners (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    customer_rsa_public_key TEXT,
    customer_ed25519_public_key VARCHAR(1024),
    system_rsa_public_key TEXT,
    system_ed25519_public_key VARCHAR(1024),
    key_fingerprint VARCHAR(128),
    
    -- Encrypted at application level (AES-256-GCM)
    keystore_password VARCHAR(1024),  -- Encrypted
    admin_encrypted_keystore_password VARCHAR(2048),  -- Encrypted
    
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    INDEX idx_name (name),
    INDEX idx_fingerprint (key_fingerprint),
    INDEX idx_active (active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- KEY METADATA (1-1 với Partner)
-- ============================================================
CREATE TABLE IF NOT EXISTS key_metadata (
    id VARCHAR(64) PRIMARY KEY,
    partner_id VARCHAR(64) NOT NULL UNIQUE,
    current_key_version VARCHAR(50),
    previous_key_version VARCHAR(50),
    last_rotated_at TIMESTAMP NULL,
    rotation_policy VARCHAR(50) DEFAULT 'AUTOMATIC',
    rotation_interval_days INT DEFAULT 90,
    next_rotation_due TIMESTAMP NULL,
    max_key_versions INT DEFAULT 5,
    key_algorithm VARCHAR(50) DEFAULT 'RSA',
    key_size INT DEFAULT 4096,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_key_metadata_partner FOREIGN KEY (partner_id) REFERENCES partners(id) ON DELETE CASCADE,
    INDEX idx_partner_id (partner_id),
    INDEX idx_next_rotation (next_rotation_due)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- KEY VERSIONS (1-N với Partner)
-- ============================================================
CREATE TABLE IF NOT EXISTS key_versions (
    id VARCHAR(128) PRIMARY KEY,
    partner_id VARCHAR(64) NOT NULL,
    key_type VARCHAR(50) NOT NULL,
    key_version VARCHAR(50) NOT NULL,
    fingerprint VARCHAR(128),
    public_key_data TEXT NOT NULL,
    encrypted_private_key TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    deprecated BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT fk_key_version_partner FOREIGN KEY (partner_id) REFERENCES partners(id) ON DELETE CASCADE,
    INDEX idx_partner_id (partner_id),
    INDEX idx_key_type_version (key_type, key_version),
    INDEX idx_fingerprint (fingerprint),
    INDEX idx_active (active),
    INDEX idx_created_at (created_at),
    UNIQUE KEY uk_partner_key (partner_id, key_type, key_version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- AUDIT LOGS (Partitioned by HOUR for high-volume)
-- Optimized: Use efficient types, avoid TEXT, add constraints
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id CHAR(36) NOT NULL DEFAULT (UUID()),
    correlation_id CHAR(36),
    user_id VARCHAR(64),
    partner_id VARCHAR(64),
    action VARCHAR(100) NOT NULL,
    sender_id VARCHAR(64),
    recipient_id VARCHAR(64),
    payload_type VARCHAR(50) NULL,
    details VARCHAR(2000) NULL COMMENT 'Limited size to avoid row overflow',
    success TINYINT(1) NOT NULL DEFAULT 1 COMMENT 'Boolean as TINYINT',
    timestamp TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    ip_address VARCHAR(45) NULL COMMENT 'IPv4/IPv6 max length',
    PRIMARY KEY (id, timestamp),
    INDEX idx_timestamp (timestamp),
    INDEX idx_action (action),
    INDEX idx_user_id (user_id),
    INDEX idx_partner_id (partner_id),
    INDEX idx_correlation_id (correlation_id),
    INDEX idx_success (success),
    INDEX idx_timestamp_action (timestamp, action),
    INDEX idx_timestamp_partner (timestamp, partner_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
PARTITION BY RANGE (UNIX_TIMESTAMP(timestamp)) (
    -- Hourly partitions for current week (168 partitions)
    PARTITION p2025050100 VALUES LESS THAN (1746057600),
    PARTITION p2025050101 VALUES LESS THAN (1746061200),
    PARTITION p2025050102 VALUES LESS THAN (1746064800),
    PARTITION p2025050103 VALUES LESS THAN (1746068400),
    PARTITION p2025050104 VALUES LESS THAN (1746072000),
    PARTITION p2025050105 VALUES LESS THAN (1746075600),
    PARTITION p2025050106 VALUES LESS THAN (1746079200),
    PARTITION p2025050107 VALUES LESS THAN (1746082800),
    PARTITION p2025050108 VALUES LESS THAN (1746086400),
    PARTITION p2025050109 VALUES LESS THAN (1746090000),
    PARTITION p2025050110 VALUES LESS THAN (1746093600),
    PARTITION p2025050111 VALUES LESS THAN (1746097200),
    PARTITION p2025050112 VALUES LESS THAN (1746100800),
    PARTITION p2025050113 VALUES LESS THAN (1746104400),
    PARTITION p2025050114 VALUES LESS THAN (1746108000),
    PARTITION p2025050115 VALUES LESS THAN (1746111600),
    PARTITION p2025050116 VALUES LESS THAN (1746115200),
    PARTITION p2025050117 VALUES LESS THAN (1746118800),
    PARTITION p2025050118 VALUES LESS THAN (1746122400),
    PARTITION p2025050119 VALUES LESS THAN (1746126000),
    PARTITION p2025050120 VALUES LESS THAN (1746129600),
    PARTITION p2025050121 VALUES LESS THAN (1746133200),
    PARTITION p2025050122 VALUES LESS THAN (1746136800),
    PARTITION p2025050123 VALUES LESS THAN (1746140400),
    -- Future partition (auto-split by procedure)
    PARTITION p_future VALUES LESS THAN MAXVALUE
);

-- ============================================================
-- ENVELOPE LOGS (1-N với Partner và User)
-- ============================================================
CREATE TABLE IF NOT EXISTS envelope_logs (
    id VARCHAR(64) PRIMARY KEY,
    partner_id VARCHAR(64),
    user_id VARCHAR(64),
    envelope_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    message_type VARCHAR(10),
    mti VARCHAR(4),
    processing_code VARCHAR(6),
    transaction_id VARCHAR(64),
    correlation_id VARCHAR(128),
    nonce VARCHAR(128),
    processing_time_ms BIGINT,
    key_version_used VARCHAR(50),
    algorithm VARCHAR(50),
    error_message VARCHAR(1000),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_envelope_partner FOREIGN KEY (partner_id) REFERENCES partners(id) ON DELETE SET NULL,
    CONSTRAINT fk_envelope_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_partner_id (partner_id),
    INDEX idx_user_id (user_id),
    INDEX idx_created_at (created_at),
    INDEX idx_status (status),
    INDEX idx_envelope_type (envelope_type),
    INDEX idx_correlation_id (correlation_id),
    INDEX idx_transaction_id (transaction_id),
    INDEX idx_timestamp_status (created_at, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- PARTNER MANAGERS (N-M Join Table)
-- ============================================================
CREATE TABLE IF NOT EXISTS partner_managers (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL,
    partner_id VARCHAR(64) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'OPERATOR',
    assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    CONSTRAINT fk_pm_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_pm_partner FOREIGN KEY (partner_id) REFERENCES partners(id) ON DELETE CASCADE,
    UNIQUE KEY uk_user_partner (user_id, partner_id),
    INDEX idx_user_id (user_id),
    INDEX idx_partner_id (partner_id),
    INDEX idx_active (active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- ENCRYPTION KEY STORE (Application-managed)
-- ============================================================
CREATE TABLE IF NOT EXISTS encryption_keys (
    id VARCHAR(64) PRIMARY KEY,
    key_type VARCHAR(50) NOT NULL,
    key_version VARCHAR(50) NOT NULL,
    encrypted_key_data TEXT NOT NULL,
    key_checksum VARCHAR(64),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    INDEX idx_key_type_version (key_type, key_version),
    INDEX idx_active (active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- IDEMPOTENCY CACHE (For duplicate request prevention)
-- ============================================================
CREATE TABLE IF NOT EXISTS idempotency_keys (
    key_hash VARCHAR(128) PRIMARY KEY,
    request_hash VARCHAR(256),
    response_data TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    INDEX idx_expires_at (expires_at),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- VIEW: Partner with Key Info
-- ============================================================
CREATE OR REPLACE VIEW v_partner_key_info AS
SELECT 
    p.id,
    p.name,
    p.active,
    p.key_fingerprint,
    km.current_key_version,
    km.next_rotation_due,
    km.rotation_policy,
    km.rotation_interval_days,
    (SELECT COUNT(*) FROM key_versions kv WHERE kv.partner_id = p.id AND kv.active = TRUE) AS active_keys
FROM partners p
LEFT JOIN key_metadata km ON km.partner_id = p.id;

-- ============================================================
-- VIEW: User Activity Summary
-- ============================================================
CREATE OR REPLACE VIEW v_user_activity AS
SELECT 
    u.id,
    u.username,
    u.email,
    u.role,
    u.active,
    COUNT(DISTINCT pm.partner_id) AS managed_partners,
    COUNT(DISTINCT al.id) AS total_audit_actions,
    MAX(al.timestamp) AS last_action
FROM users u
LEFT JOIN partner_managers pm ON pm.user_id = u.id AND pm.active = TRUE
LEFT JOIN audit_logs al ON al.user_id = u.id
GROUP BY u.id, u.username, u.email, u.role, u.active;