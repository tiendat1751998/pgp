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
    public String logEncrypt(String correlationId, String senderId, String recipientId, String payloadType, boolean success) {
        AuditLog auditLog = new AuditLog();
        auditLog.setCorrelationId(correlationId);
        auditLog.setAction("ENCRYPT");
        auditLog.setSenderId(senderId);
        auditLog.setRecipientId(recipientId);
        auditLog.setPayloadType(payloadType);
        auditLog.setSuccess(success);
        
        addToBuffer(auditLog);
        return auditLog.getId();
    }

    @Async
    public String logDecrypt(String correlationId, String senderId, String recipientId, String payloadType, boolean success) {
        AuditLog auditLog = new AuditLog();
        auditLog.setCorrelationId(correlationId);
        auditLog.setAction("DECRYPT");
        auditLog.setSenderId(senderId);
        auditLog.setRecipientId(recipientId);
        auditLog.setPayloadType(payloadType);
        auditLog.setSuccess(success);
        
        addToBuffer(auditLog);
        return auditLog.getId();
    }

    @Async
    public String logKeyGeneration(String entityId, String keyType) {
        AuditLog auditLog = new AuditLog();
        auditLog.setAction("KEY_GEN");
        auditLog.setSenderId(entityId);
        auditLog.setPayloadType(keyType);
        auditLog.setSuccess(true);
        
        addToBuffer(auditLog);
        return auditLog.getId();
    }

    @Async
    public String logKeyRotation(String entityId, String oldKeyId, String newKeyId) {
        AuditLog auditLog = new AuditLog();
        auditLog.setAction("KEY_ROTATE");
        auditLog.setSenderId(entityId);
        auditLog.setPayloadType("RSA");
        auditLog.setDetails(oldKeyId + " -> " + newKeyId);
        auditLog.setSuccess(true);
        
        addToBuffer(auditLog);
        return auditLog.getId();
    }

    @Async
    public String logSecurityEvent(String entityId, String eventType, String details) {
        AuditLog auditLog = new AuditLog();
        auditLog.setAction("SECURITY_EVENT");
        auditLog.setSenderId(entityId);
        auditLog.setPayloadType(eventType);
        auditLog.setDetails(details);
        auditLog.setSuccess(true);
        
        addToBuffer(auditLog);
        return auditLog.getId();
    }

    private void addToBuffer(AuditLog auditLog) {
        if (auditBuffer.size() >= MAX_LOG_SIZE) {
            if (cleanupLock.tryLock()) {
                try {
                    if (auditBuffer.size() >= MAX_LOG_SIZE) {
                        List<AuditLog> discarded = new ArrayList<>(1000);
                        int removed = auditBuffer.drainTo(discarded, 1000);
                        log.warn("Audit buffer reached limit. Discarded {} oldest logs.", removed);
                    }
                } finally {
                    cleanupLock.unlock();
                }
            }
        }
        auditBuffer.offer(auditLog);
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
                log.info("Flushed {} audit logs to database", batch.size());
            } catch (Exception e) {
                log.error("Failed to flush audit logs to database: {}", e.getMessage());
                // In case of error, put back to buffer (though they go to the end)
                auditBuffer.addAll(batch);
            }
        }
    }
}