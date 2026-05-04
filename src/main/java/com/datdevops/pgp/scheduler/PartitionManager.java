package com.datdevops.pgp.scheduler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Component
public class PartitionManager {

    private static final Logger log = LoggerFactory.getLogger(PartitionManager.class);

    private final JdbcTemplate jdbcTemplate;

    @Value("${app.partition.retention-days:30}")
    private int retentionDays;

    @Value("${app.partition.pre-create-hours:48}")
    private int preCreateHours;

    public PartitionManager(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @PostConstruct
    public void init() {
        createInitialPartitions();
    }

    @Scheduled(cron = "0 0 * * * *")  // Every hour at minute 0
    public void managePartitions() {
        log.info("Running partition management...");
        createFuturePartitions();
        dropOldPartitions();
    }

    private void createInitialPartitions() {
        try {
            createFuturePartitions();
        } catch (Exception e) {
            log.warn("Initial partition creation skipped: {}", e.getMessage());
        }
    }

    public void createFuturePartitions() {
        String sql = """
            SELECT PARTITION_NAME 
            FROM information_schema.PARTITIONS 
            WHERE TABLE_SCHEMA = DATABASE() 
            AND TABLE_NAME = 'audit_logs' 
            AND PARTITION_NAME = ?
            """;

        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMddHH");

        for (int i = 1; i <= preCreateHours; i++) {
            LocalDateTime futureHour = now.plusHours(i);
            String partitionName = "p" + futureHour.format(formatter);

            try {
                Integer count = jdbcTemplate.queryForObject(sql, Integer.class, partitionName);
                if (count == null || count == 0) {
                    long unixTimestamp = futureHour.atZone(java.time.ZoneId.of("UTC")).toEpochSecond();
                    String alterSql = String.format(
                        "ALTER TABLE audit_logs ADD PARTITION (PARTITION %s VALUES LESS THAN (%d))",
                        partitionName, unixTimestamp
                    );
                    jdbcTemplate.execute(alterSql);
                    log.info("Created partition: {}", partitionName);
                }
            } catch (Exception e) {
                log.debug("Partition {} may already exist: {}", partitionName, e.getMessage());
            }
        }
    }

    public void dropOldPartitions() {
        String sql = """
            SELECT PARTITION_NAME, PARTITION_DESCRIPTION
            FROM information_schema.PARTITIONS 
            WHERE TABLE_SCHEMA = DATABASE() 
            AND TABLE_NAME = 'audit_logs' 
            AND PARTITION_NAME LIKE 'p20%'
            AND PARTITION_DESCRIPTION < UNIX_TIMESTAMP(DATE_SUB(NOW(), INTERVAL ? DAY))
            """;

        try {
            var partitions = jdbcTemplate.query(sql, (rs, row) -> new PartitionInfo(
                rs.getString("PARTITION_NAME"),
                rs.getLong("PARTITION_DESCRIPTION")
            ), retentionDays);

            for (PartitionInfo p : partitions) {
                try {
                    String dropSql = String.format("ALTER TABLE audit_logs DROP PARTITION %s", p.name);
                    jdbcTemplate.execute(dropSql);
                    log.info("Dropped old partition: {}", p.name);
                } catch (Exception e) {
                    log.warn("Failed to drop partition {}: {}", p.name, e.getMessage());
                }
            }
        } catch (Exception e) {
            log.debug("No partitions to drop: {}", e.getMessage());
        }
    }

    record PartitionInfo(String name, long description) {}
}