package com.datdevops.pgp.service;

import com.datdevops.pgp.entity.AuditLog;
import com.datdevops.pgp.repository.AuditLogRepository;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import jakarta.annotation.PreDestroy;

/**
 * Performant, asynchronous Audit Service with per-partner quota to prevent DB exhaustion.
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);
    private static final int MAX_LOG_SIZE = 20000;
    private static final int BATCH_SIZE = 500;
    private static final int MAX_AUDITS_PER_PARTNER = 10000;

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS")
            .withZone(ZoneOffset.UTC);

    private final LinkedBlockingQueue<AuditLog> auditBuffer;
    private final AuditLogRepository auditLogRepository;
    private final Cache<String, AtomicInteger> partnerAuditCount;

    public AuditService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
        this.auditBuffer = new LinkedBlockingQueue<>(MAX_LOG_SIZE);
        this.partnerAuditCount = Caffeine.newBuilder()
                .maximumSize(1000)
                .expireAfterWrite(1, TimeUnit.MINUTES)
                .build();
    }

    @PreDestroy
    public void onShutdown() {
        log.info("[SHUTDOWN] Flushing {} remaining audit logs to database...", auditBuffer.size());
        flushToDatabase();
        log.info("[SHUTDOWN] Audit log flush complete.");
    }

    /** @deprecated For testing only */
    @Deprecated
    public AuditService() {
        this(null);
    }

    @Async
    public void logEncrypt(String correlationId, String senderId, String recipientId, String payloadType,
            boolean success) {
        AuditLog auditLog = createBaseLog("ENCRYPT", senderId, success);
        auditLog.setCorrelationId(correlationId);
        auditLog.setRecipientId(recipientId);
        auditLog.setPayloadType(payloadType);
        addToBuffer(auditLog);
    }

    @Async
    public void logDecrypt(String correlationId, String senderId, String recipientId, String payloadType,
            boolean success) {
        AuditLog auditLog = createBaseLog("DECRYPT", senderId, success);
        auditLog.setCorrelationId(correlationId);
        auditLog.setRecipientId(recipientId);
        auditLog.setPayloadType(payloadType);
        addToBuffer(auditLog);
    }

    @Async
    public void logKeyGeneration(String entityId, String keyType) {
        AuditLog auditLog = createBaseLog("KEY_GEN", entityId, true);
        auditLog.setPayloadType(keyType);
        addToBuffer(auditLog);
    }

    @Async
    public void logKeyRotation(String entityId, String oldKeyId, String newKeyId) {
        AuditLog auditLog = createBaseLog("KEY_ROTATE", entityId, true);
        auditLog.setPayloadType("RSA/ED25519");
        auditLog.setDetails(oldKeyId + " -> " + newKeyId);
        addToBuffer(auditLog);
    }

    @Async
    public void logSecurityEvent(String entityId, String eventType, String details) {
        AuditLog auditLog = createBaseLog("SECURITY_EVENT", entityId, true);
        auditLog.setPayloadType(eventType);
        auditLog.setDetails(details);
        addToBuffer(auditLog);
    }

    private AuditLog createBaseLog(String action, String senderId, boolean success) {
        AuditLog auditLog = new AuditLog();
        auditLog.setAction(action);
        auditLog.setSenderId(senderId);
        auditLog.setSuccess(success);
        auditLog.setTimestamp(Instant.now()); // CRITICAL: Fix for NPE in cleanup
        return auditLog;
    }

    private void addToBuffer(AuditLog auditLog) {
        try {
            String senderId = sanitize(auditLog.getSenderId());
            AtomicInteger count = partnerAuditCount.get(senderId, k -> new AtomicInteger(0));

            if (count.get() >= MAX_AUDITS_PER_PARTNER) {
                log.warn("[AUDIT_QUOTA_EXCEEDED] Partner {} exceeded quota, dropping audit", senderId);
                return;
            }

            boolean accepted = auditBuffer.offer(auditLog, 2, TimeUnit.SECONDS);
            if (!accepted) {
                log.error("[CRITICAL] Audit buffer overflow! Data loss for action={} by={}",
                        sanitize(auditLog.getAction()), senderId);
            } else {
                count.incrementAndGet();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Audit log interrupted", e);
        }
    }

    public int getLogSize() {
        return auditBuffer.size();
    }

    public String formatTimestamp(long timestamp) {
        return FORMATTER.format(Instant.ofEpochMilli(timestamp));
    }

    public List<AuditLog> getRecentLogs(int limit) {
        return Collections.unmodifiableList(auditBuffer.stream()
                .limit(limit)
                .toList());
    }

    @Scheduled(fixedRate = 2000) // Faster flush for high TPS
    public void flushToDatabase() {
        if (auditLogRepository == null || auditBuffer.isEmpty()) {
            return;
        }

        List<AuditLog> batch = new ArrayList<>(BATCH_SIZE);
        auditBuffer.drainTo(batch, BATCH_SIZE);

        if (!batch.isEmpty()) {
            try {
                auditLogRepository.saveAll(batch);
            } catch (Exception e) {
                log.error("[AUDIT_FAILURE] DB persistence failed for {} logs. Attempting recovery.", batch.size(), e);
                // Attempt to put logs back at the END of the buffer to retry later
                // Note: This breaks strict chronological order in DB but prevents total data
                // loss.
                for (AuditLog logItem : batch) {
                    if (!auditBuffer.offer(logItem)) {
                        log.warn("[AUDIT_LOST] Buffer full during recovery. Log lost: {}", logItem);
                    }
                }
            }
        }
    }

    @Scheduled(cron = "0 0 * * * ?") // Hourly cleanup
    public void cleanupOldBufferEntries() {
        long cutoff = System.currentTimeMillis() - TimeUnit.HOURS.toMillis(2);
        auditBuffer.removeIf(logItem -> logItem.getTimestamp().toEpochMilli() < cutoff);
        log.debug("[AUDIT_CLEANUP] Buffer cleanup completed");
    }

    private String sanitize(String value) {
        if (value == null) return "null";
        // CRITICAL: Prevent log forgery by removing newlines and control characters
        return value.replaceAll("[\r\n]", "_").replaceAll("[^\\p{Print}]", "?");
    }
}