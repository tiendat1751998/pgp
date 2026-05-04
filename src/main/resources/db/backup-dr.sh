-- ============================================================
-- BACKUP & DISASTER RECOVERY CONFIGURATION
-- MariaDB/MySQL
-- ============================================================

-- ============================================================
-- 1. Enable Binary Logging for Point-in-Time Recovery
-- ============================================================
-- Add to my.cnf/mariadb.conf:
-- [mysqld]
-- log_bin = /var/log/mysql/mariadb-bin
-- binlog_format = ROW
-- binlog_row_image = FULL
-- expire_logs_days = 7
-- max_binlog_size = 100M
-- sync_binlog = 1
-- binlog_checksum = CRC32

-- ============================================================
-- 2. Backup User (Least Privilege)
-- ============================================================
CREATE USER IF NOT EXISTS 'pgp_backup'@'localhost' IDENTIFIED BY 'CHANGE_ME_STRONG_PASSWORD';
GRANT SELECT, LOCK TABLES, SHOW VIEW, EVENT, TRIGGER ON pgpdb.* TO 'pgp_backup'@'localhost';
GRANT REPLICATION CLIENT ON *.* TO 'pgp_backup'@'localhost';

-- ============================================================
-- 3. Full Backup Script (Run daily via cron)
-- ============================================================
-- #!/bin/bash
-- DATE=$(date +%Y%m%d_%H%M%S)
-- BACKUP_DIR="/backup/pgp"
-- PASS_FILE="/root/.my.cnf"
-- 
-- # Lock tables and backup
-- mysqldump --single-transaction --quick --lock-tables=false \
--   --master-data=2 --flush-logs \
--   --routines --triggers --events \
--   --password=$(cat $PASS_FILE | grep password | cut -d'=' -f2) \
--   pgpdb | gzip > $BACKUP_DIR/pgpdb_full_$DATE.sql.gz
-- 
-- # Verify backup
-- gunzip -t $BACKUP_DIR/pgpdb_full_$DATE.sql.gz && echo "Backup OK" || echo "Backup FAILED"
-- 
-- # Remove backups older than 30 days
-- find $BACKUP_DIR -name "*.sql.gz" -mtime +30 -delete

-- ============================================================
-- 4. Incremental Backup (Run hourly via cron)
-- ============================================================
-- #!/bin/bash
-- DATE=$(date +%Y%m%d_%H%M%S)
-- BACKUP_DIR="/backup/pgp/incremental"
-- 
-- # Get current binlog position
-- mysql -e "SHOW MASTER STATUS\G" > $BACKUP_DIR/position_$DATE.txt
-- 
-- # Copy binary logs since last backup
-- cp /var/log/mysql/mariadb-bin.* $BACKUP_DIR/

-- ============================================================
-- 5. Point-in-Time Recovery Script
-- ============================================================
-- # Restore to specific point in time:
-- # 1. Restore full backup
-- # 2. Apply binary logs up to point
-- 
-- # Example: Restore to 2025-05-01 10:30:00
-- mysql pgpdb < pgpdb_full_20250501.sql.gz
-- mysqlbinlog --stop-datetime="2025-05-01 10:30:00" \
--   /backup/pgp/incremental/mariadb-bin.000001 | mysql pgpdb

-- ============================================================
-- 6. Encryption at Rest (TDE)
-- ============================================================
-- MariaDB:
-- CREATE TABLE t1 (id INT) ENCRYPTED=YES ENCRYPTION_KEY_ID=1;

-- MySQL 8.0+:
-- ALTER TABLE audit_logs ENCRYPTION='Y';

-- ============================================================
-- 7. Offsite Backup (S3/GCS)
-- ============================================================
-- # Upload to S3 (encrypted)
-- aws s3 cp pgpdb_full_$(date +%Y%m%d).sql.gz s3://pgp-backups/production/ \
--   --sse AES256 --storage-class STANDARD_IA

-- ============================================================
-- 8. Restore Test (Run monthly)
-- ============================================================
-- #!/bin/bash
-- echo "Testing backup restore..."
-- mysql -e "DROP DATABASE IF EXISTS pgpdb_test"
-- mysql -e "CREATE DATABASE pgpdb_test"
-- gunzip -c pgpdb_full_latest.sql.gz | mysql pgpdb_test
-- ROW_COUNT=$(mysql -e "SELECT COUNT(*) FROM pgpdb_test.users" -N)
-- if [ "$ROW_COUNT" -gt 0 ]; then echo "Restore OK: $ROW_COUNT rows"; else echo "Restore FAILED"; fi