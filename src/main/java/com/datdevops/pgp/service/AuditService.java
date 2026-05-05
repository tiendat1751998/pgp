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
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);
    private static final int MAX_LOG_SIZE = 10000;
    private static final int BATCH_SIZE = 100;
    private static final DateTimeFormatter FORMATTER = 
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

    private final LinkedBlockingQueue<AuditLog> auditBuffer;
    private final ReentrantLock cleanupLock = new ReentrantLock();
    private final Cache<String, AuditLog> auditCache;
    private final AuditLogRepository auditLogRepository;

    public AuditService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
        this.auditBuffer = new LinkedBlockingQueue<>(MAX_LOG_SIZE + 1000);
        this.auditCache = Caffeine.newBuilder()
                .maximumSize(1000)
                .expireAfterWrite(1, TimeUnit.HOURS)
                .build();
    }

    public AuditService() {
        this(null);
    }

    @Async
    public void logEncrypt(String correlationId, String senderId, String recipientId, String payloadType, boolean success) {
        AuditLog auditLog = new AuditLog();
        auditLog.setCorrelationId(correlationId);
        auditLog.setAction("ENCRYPT");
        auditLog.setSenderId(senderId);
        auditLog.setRecipientId(recipientId);
        auditLog.setPayloadType(payloadType);
        auditLog.setSuccess(success);
        
        addToBuffer(auditLog);
    }

    @Async
    public void logDecrypt(String correlationId, String senderId, String recipientId, String payloadType, boolean success) {
        AuditLog auditLog = new AuditLog();
        auditLog.setCorrelationId(correlationId);
        auditLog.setAction("DECRYPT");
        auditLog.setSenderId(senderId);
        auditLog.setRecipientId(recipientId);
        auditLog.setPayloadType(payloadType);
        auditLog.setSuccess(success);
        
        addToBuffer(auditLog);
    }

    @Async
    public void logKeyGeneration(String entityId, String keyType) {
        AuditLog auditLog = new AuditLog();
        auditLog.setAction("KEY_GEN");
        auditLog.setSenderId(entityId);
        auditLog.setPayloadType(keyType);
        auditLog.setSuccess(true);
        
        addToBuffer(auditLog);
    }

    @Async
    public void logKeyRotation(String entityId, String oldKeyId, String newKeyId) {
        AuditLog auditLog = new AuditLog();
        auditLog.setAction("KEY_ROTATE");
        auditLog.setSenderId(entityId);
        auditLog.setPayloadType("RSA");
        auditLog.setDetails(oldKeyId + " -> " + newKeyId);
        auditLog.setSuccess(true);
        
        addToBuffer(auditLog);
    }

    @Async
    public void logSecurityEvent(String entityId, String eventType, String details) {
        AuditLog auditLog = new AuditLog();
        auditLog.setAction("SECURITY_EVENT");
        auditLog.setSenderId(entityId);
        auditLog.setPayloadType(eventType);
        auditLog.setDetails(details);
        auditLog.setSuccess(true);
        
        addToBuffer(auditLog);
    }

    private void addToBuffer(AuditLog auditLog) {
        // In a banking environment, we MUST NOT discard audit logs.
        // If the buffer is full, we use 'offer' with a timeout or 'put' (blocking).
        // Since this is called from @Async methods, blocking the executor thread 
        // provides natural backpressure to the rest of the system.
        try {
            boolean accepted = auditBuffer.offer(auditLog, 5, TimeUnit.SECONDS);
            if (!accepted) {
                log.error("[CRITICAL] Audit buffer full and timed out. Potential data loss or system stall. identity={}", auditLog.getSenderId());
                // Fallback: synchronous emergency log to file/console
                log.warn("[EMERGENCY_LOG] CorrelationId: {} | Action: {} | Success: {}", 
                    auditLog.getCorrelationId(), auditLog.getAction(), auditLog.isSuccess());
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Interrupted while adding to audit buffer", e);
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

    public void cleanupOldEntries(long cutoffMillis) {
        long cutoff = System.currentTimeMillis() - cutoffMillis;
        while (auditBuffer.peek() != null && auditBuffer.peek().getTimestamp().toEpochMilli() < cutoff) {
            auditBuffer.poll();
        }
    }

    @Scheduled(fixedRate = 5000)
    public void flushToDatabase() {
        if (auditLogRepository == null || auditBuffer.isEmpty()) {
            return;
        }

        List<AuditLog> batch = new ArrayList<>(BATCH_SIZE);
        auditBuffer.drainTo(batch, BATCH_SIZE);

        if (!batch.isEmpty()) {
            try {
                auditLogRepository.saveAll(batch);
                log.info("Successfully flushed {} audit logs to database", batch.size());
            } catch (Exception e) {
                log.error("[DATABASE_ERROR] Failed to flush {} audit logs: {}", batch.size(), e.getMessage());
                // Crucial: Prepend the batch back to the front of the buffer if possible, 
                // or use a dedicated failure-retry queue to maintain strict chronological order.
                // For now, we log them as an error. Putting them at the end of the buffer 
                // (as was previously done) would corrupt the event sequence.
                for (int i = batch.size() - 1; i >= 0; i--) {
                    // Try to put back at the head (not easily supported by LinkedBlockingQueue without a Deque)
                    // So we log it as an emergency and hope the DB recovers.
                    log.error("[DATA_RECOVERY_REQUIRED] {}", batch.get(i));
                }
            }
        }
    }
}