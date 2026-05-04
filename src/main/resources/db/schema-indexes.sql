-- DATABASE INDEXES FOR PERFORMANCE OPTIMIZATION
-- Apply this schema for production MariaDB/MySQL

-- Partner table indexes
CREATE INDEX IF NOT EXISTS idx_partner_id ON partner(id);
CREATE INDEX IF NOT EXISTS idx_partner_fingerprint ON partner(key_fingerprint);

-- Audit log indexes - optimized for time-series queries
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_partner ON audit_log(partner_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp_type ON audit_log(timestamp, event_type);

-- User table indexes
CREATE INDEX IF NOT EXISTS idx_user_username ON app_user(username);
CREATE INDEX IF NOT EXISTS idx_user_role ON app_user(role);

-- ENCRYPTED COLUMNS (if using Transparent Data Encryption)
-- ALTER TABLE partner ENCRYPTED=YES;
-- ALTER TABLE audit_log ENCRYPTED=YES;

-- PARTITIONING FOR AUDIT LOG (for high-volume)
-- For MariaDB: Partition by month for audit_log
-- ALTER TABLE audit_log PARTITION BY RANGE (UNIX_TIMESTAMP(timestamp)) (
--     PARTITION p202501 VALUES LESS THAN (1735689600),
--     PARTITION p202502 VALUES LESS THAN (1738281600),
--     PARTITION p202503 VALUES LESS THAN (1740960000)
-- );

-- BACKUP ENCRYPTION
-- Use mysqldump with encryption:
-- mysqldump --single-transaction --quick --lock-tables=false | gzip | openssl enc -aes-256-cbc -salt -pbkdf2 -out backup.sql.gz.enc

-- OR use MariaDB/MySQL native encryption:
-- mysqldump --single-transaction --encrypt -p -r backup.sql