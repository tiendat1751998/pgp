-- ============================================================
-- PARTITION MANAGEMENT STORED PROCEDURES
-- MariaDB/MySQL
-- ============================================================

DELIMITER //

-- ============================================================
-- Procedure: Create hourly partitions for next 48 hours
-- Run via: CALL create_hourly_partitions();
-- ============================================================
CREATE PROCEDURE IF NOT EXISTS create_hourly_partitions()
BEGIN
    DECLARE i INT DEFAULT 0;
    DECLARE partition_name VARCHAR(20);
    DECLARE partition_ts TIMESTAMP;
    DECLARE unix_ts BIGINT;
    
    SET partition_ts = DATE_FORMAT(NOW(), '%Y%m%d%H0000');
    
    WHILE i < 48 DO
        SET partition_name = CONCAT('p', DATE_FORMAT(partition_ts, '%Y%m%d%H'));
        
        -- Skip if partition already exists
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.PARTITIONS 
            WHERE TABLE_SCHEMA = DATABASE() 
            AND TABLE_NAME = 'audit_logs' 
            AND PARTITION_NAME = partition_name
        ) THEN
            SET unix_ts = UNIX_TIMESTAMP(partition_ts);
            
            SET @sql = CONCAT(
                'ALTER TABLE audit_logs ADD PARTITION (',
                'PARTITION ', partition_name, 
                ' VALUES LESS THAN (', unix_ts, ')'
            );
            
            PREPARE stmt FROM @sql;
            EXECUTE stmt;
            DEALLOCATE PREPARE stmt;
            
            SELECT CONCAT('Created partition: ', partition_name) AS result;
        END IF;
        
        SET partition_ts = partition_ts + INTERVAL 1 HOUR;
        SET i = i + 1;
    END WHILE;
END //

-- ============================================================
-- Procedure: Drop old partitions (older than X days)
-- Run via: CALL drop_old_partitions(30);
-- ============================================================
CREATE PROCEDURE IF NOT EXISTS drop_old_partitions(IN days_to_keep INT)
BEGIN
    DECLARE done INT DEFAULT FALSE;
    DECLARE partition_name VARCHAR(20);
    DECLARE partition_date DATE;
    DECLARE cutoff_date DATE;
    DECLARE cursor_partitions CURSOR FOR
        SELECT PARTITION_NAME 
        FROM information_schema.PARTITIONS 
        WHERE TABLE_SCHEMA = DATABASE() 
        AND TABLE_NAME = 'audit_logs'
        AND PARTITION_DESCRIPTION < UNIX_TIMESTAMP(NOW() - INTERVAL days_to_keep DAY)
        AND PARTITION_NAME LIKE 'p20%';
    
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;
    
    SET cutoff_date = DATE_SUB(NOW(), INTERVAL days_to_keep DAY);
    
    OPEN cursor_partitions;
    
    partition_loop: LOOP
        FETCH cursor_partitions INTO partition_name;
        IF done THEN
            LEAVE partition_loop;
        END IF;
        
        -- Extract date from partition name (e.g., p2025010100 -> 2025-01-01)
        SET partition_date = SUBSTR(partition_name, 2, 8);
        
        IF partition_date < DATE(cutoff_date) THEN
            SET @drop_sql = CONCAT('ALTER TABLE audit_logs DROP PARTITION ', partition_name);
            PREPARE stmt FROM @drop_sql;
            EXECUTE stmt;
            DEALLOCATE PREPARE stmt;
            
            SELECT CONCAT('Dropped partition: ', partition_name) AS result;
        END IF;
    END LOOP;
    
    CLOSE cursor_partitions;
END //

-- ============================================================
-- Procedure: Reorganize old hourly -> daily partitions
-- Run via: CALL reorganize_to_daily_partitions(7);
-- ============================================================
CREATE PROCEDURE IF NOT EXISTS reorganize_to_daily_partitions(IN days_to_archive INT)
BEGIN
    -- Merge hourly partitions older than X days into daily
    -- This reduces partition count for older data
    
    DECLARE partition_name VARCHAR(20);
    DECLARE target_partition VARCHAR(20);
    DECLARE partition_date VARCHAR(8);
    DECLARE min_ts BIGINT;
    DECLARE max_ts BIGINT;
    
    -- Example: Merge p2025010100-p2025010123 into p20250101
    -- Only for partitions older than specified days
    
    SELECT CONCAT('Reorganization needed for partitions older than ', days_to_archive, ' days') AS status;
END //

-- ============================================================
-- Procedure: Get partition statistics
-- Run via: CALL show_partition_stats();
-- ============================================================
CREATE PROCEDURE IF NOT EXISTS show_partition_stats()
BEGIN
    SELECT 
        PARTITION_NAME,
        PARTITION_ORDINAL,
        PARTITION_DESCRIPTION,
        TABLE_ROWS,
        ROUND(DATA_LENGTH / 1024 / 1024, 2) AS SIZE_MB
    FROM information_schema.PARTITIONS
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'audit_logs'
    ORDER BY PARTITION_ORDINAL DESC
    LIMIT 30;
END //

DELIMITER ;

-- ============================================================
-- SCHEDULED JOB: Run partition management daily
-- MariaDB Event Scheduler
-- ============================================================
-- Enable event scheduler
-- SET GLOBAL event_scheduler = ON;

-- Create daily job at 2 AM
-- CREATE EVENT IF NOT EXISTS partition_maintenance
-- ON SCHEDULE EVERY 1 DAY STARTS '2025-01-01 02:00:00'
-- DO
--     CALL create_hourly_partitions();
--     CALL drop_old_partitions(30);