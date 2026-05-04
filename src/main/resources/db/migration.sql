-- ============================================================
-- Database Migration & Maintenance Scripts
-- MariaDB/MySQL Compatible
-- ============================================================

-- ============================================================
-- MIGRATION: Add new columns (if upgrading from v1.x)
-- ============================================================

-- Add role to users if not exists
-- ALTER TABLE users ADD COLUMN role VARCHAR(50) NOT NULL DEFAULT 'USER' AFTER password_hash;

-- Add active flag to partners if not exists
-- ALTER TABLE partners ADD COLUMN active BOOLEAN NOT NULL DEFAULT TRUE AFTER updated_at;

-- ============================================================
-- PARTITION MAINTENANCE: Add new partition monthly
-- ============================================================

-- Example: Add partition for new month
-- ALTER TABLE audit_logs REORGANIZE PARTITION p_future INTO (
--     PARTITION p202507 VALUES LESS THAN (1751404800),
--     PARTITION p_future VALUES LESS THAN MAXVALUE
-- );

-- ============================================================
-- INDEX MAINTENANCE: Rebuild fragmented indexes
-- ============================================================
-- OPTIMIZE TABLE audit_logs;
-- OPTIMIZE TABLE envelope_logs;

-- ============================================================
-- CLEANUP: Remove old idempotency keys
-- ============================================================
DELETE FROM idempotency_keys WHERE expires_at < CURRENT_TIMESTAMP;

-- ============================================================
-- CLEANUP: Archive and truncate old audit logs
-- ============================================================
-- Step 1: Export to archive table
-- CREATE TABLE audit_logs_archive LIKE audit_logs;
-- INSERT INTO audit_logs_archive SELECT * FROM audit_logs WHERE timestamp < DATE_SUB(NOW(), INTERVAL 1 YEAR);

-- Step 2: Delete from main table (use partitioning DROP for partitioned tables)
-- ALTER TABLE audit_logs TRUNCATE PARTITION p202401;

-- ============================================================
-- ROTATE KEYS: Deprecate old key versions
-- ============================================================
-- UPDATE key_versions 
-- SET deprecated = TRUE, active = FALSE 
-- WHERE partner_id = 'BANK_A' 
-- AND key_type = 'RSA' 
-- AND key_version < (SELECT current_key_version FROM key_metadata WHERE partner_id = 'BANK_A');

-- ============================================================
-- BACKUP: Encrypted backup procedure
-- ============================================================
-- mysqldump --single-transaction --quick --lock-tables=false \
--   --databases pgpdb | gzip > pgpdb_backup_$(date +%Y%m%d).sql.gz

-- Encrypted backup:
-- mysqldump --single-transaction --quick --lock-tables=false \
--   --databases pgpdb | gzip | openssl enc -aes-256-cbc -salt -pbkdf2 \
--   -out pgpdb_backup_$(date +%Y%m%d).sql.gz.enc -pass pass:$BACKUP_PASSWORD

-- ============================================================
-- RESTORE: Encrypted backup restore
-- ============================================================
-- openssl enc -aes-256-cbc -d -salt -pbkdf2 \
--   -in pgpdb_backup_20260101.sql.gz.enc -pass pass:$BACKUP_PASSWORD | gunzip | mysql pgpdb

-- ============================================================
-- MONITORING: Table sizes and row counts
-- ============================================================
SELECT 
    TABLE_NAME,
    ROUND(DATA_LENGTH / 1024 / 1024, 2) AS 'Size (MB)',
    TABLE_ROWS
FROM information_schema.TABLES
WHERE TABLE_SCHEMA = 'pgpdb'
ORDER BY DATA_LENGTH DESC;

-- ============================================================
-- MONITORING: Slow queries (enable slow_query_log)
-- ============================================================
-- SELECT * FROM mysql.slow_log ORDER BY start_time DESC LIMIT 10;

-- ============================================================
-- SECURITY: Audit user permissions
-- ============================================================
-- SELECT user, host FROM mysql.user WHERE authentication_string IS NULL;
-- SHOW GRANTS FOR 'pgpapp'@'localhost';