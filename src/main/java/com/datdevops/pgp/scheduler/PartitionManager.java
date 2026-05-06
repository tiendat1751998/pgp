package com.datdevops.pgp.scheduler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Manages database partitions for audit logs.
 * Hardened with SQL injection protection and consistent UTC time handling.
 */
@Component
public class PartitionManager {

    private static final Logger log = LoggerFactory.getLogger(PartitionManager.class);
    private static final Pattern PARTITION_NAME_PATTERN = Pattern.compile("^p[0-9]{10}$");
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyyMMddHH").withZone(ZoneId.of("UTC"));

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

    @Scheduled(cron = "0 0 * * * *")
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
        String checkSql = """
            SELECT COUNT(*) 
            FROM information_schema.PARTITIONS 
            WHERE TABLE_SCHEMA = DATABASE() 
            AND TABLE_NAME = 'audit_logs' 
            AND PARTITION_NAME = ?
            """;

        Instant now = Instant.now();

        for (int i = 1; i <= preCreateHours; i++) {
            Instant futureInstant = now.plus(i, ChronoUnit.HOURS);
            String partitionName = "p" + FORMATTER.format(futureInstant);

            try {
                // Fix Logic Bug #151: Use COUNT(*) instead of selecting PARTITION_NAME
                Integer count = jdbcTemplate.queryForObject(checkSql, Integer.class, partitionName);
                if (count == null || count == 0) {
                    long unixTimestamp = futureInstant.truncatedTo(ChronoUnit.HOURS).plus(1, ChronoUnit.HOURS).getEpochSecond();
                    
                    // Fix SQLi #150: Strict regex validation before string formatting
                    if (!PARTITION_NAME_PATTERN.matcher(partitionName).matches()) {
                        throw new SecurityException("Invalid partition name generated: " + partitionName);
                    }

                    String alterSql = String.format(
                        "ALTER TABLE audit_logs ADD PARTITION (PARTITION %s VALUES LESS THAN (%d))",
                        partitionName, unixTimestamp
                    );
                    jdbcTemplate.execute(alterSql);
                    log.info("Created partition: {}", partitionName);
                }
            } catch (Exception e) {
                log.debug("Partition {} creation attempted: {}", partitionName, e.getMessage());
            }
        }
    }

    public void dropOldPartitions() {
        String listSql = """
            SELECT PARTITION_NAME, PARTITION_DESCRIPTION
            FROM information_schema.PARTITIONS 
            WHERE TABLE_SCHEMA = DATABASE() 
            AND TABLE_NAME = 'audit_logs' 
            AND PARTITION_NAME LIKE 'p20%'
            """;

        try {
            long cutoffTimestamp = Instant.now().minus(retentionDays, ChronoUnit.DAYS).getEpochSecond();
            
            var partitions = jdbcTemplate.query(listSql, (rs, row) -> new PartitionInfo(
                rs.getString("PARTITION_NAME"),
                rs.getLong("PARTITION_DESCRIPTION")
            ));

            for (PartitionInfo p : partitions) {
                // Only drop if it matches pattern and is older than retention
                if (PARTITION_NAME_PATTERN.matcher(p.name).matches() && p.description < cutoffTimestamp) {
                    try {
                        String dropSql = String.format("ALTER TABLE audit_logs DROP PARTITION %s", p.name);
                        jdbcTemplate.execute(dropSql);
                        log.info("Dropped old partition: {}", p.name);
                    } catch (Exception e) {
                        log.warn("Failed to drop partition {}: {}", p.name, e.getMessage());
                    }
                }
            }
        } catch (Exception e) {
            log.debug("Partition cleanup error: {}", e.getMessage());
        }
    }

    record PartitionInfo(String name, long description) {}
}