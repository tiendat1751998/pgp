package com.datdevops.pgp.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class ReplayProtectionService {

    private static final Logger log = LoggerFactory.getLogger(ReplayProtectionService.class);
    private static final String NONCE_PREFIX = "pgp:nonce:";

    @Value("${app.replay-protection.ttl-seconds:300}")
    private long ttlSeconds;

    @Value("${app.replay-protection.max-size:10000}")
    private int maxCacheSize;

    private final RedisTemplate<String, Long> redisTemplate;
    private final ConcurrentMap<String, Long> localCache;

    private volatile boolean useRedis = true;
    private final AtomicInteger reconnectAttempts = new AtomicInteger(0);
    private static final int MAX_RECONNECT_ATTEMPTS = 5;

    @Value("${app.replay-protection.strict-mode:false}")
    private boolean strictMode;

    public ReplayProtectionService(RedisTemplate<String, Long> redisTemplate) {
        this.redisTemplate = redisTemplate;
        this.localCache = new ConcurrentHashMap<>();
        initMode();
    }

    public ReplayProtectionService() {
        this(null);
    }

    public ReplayProtectionService(long ttlSeconds, int maxCacheSize) {
        this(null);
        this.ttlSeconds = ttlSeconds;
        this.maxCacheSize = maxCacheSize;
    }

    private void initMode() {
        if (redisTemplate == null) {
            useRedis = false;
            return;
        }

        try {
            redisTemplate.opsForValue().get("pgp:healthcheck");
            useRedis = true;
        } catch (Exception e) {
            useRedis = false;
        }
    }

    @PostConstruct
    public void init() {
        initMode();
    }

    public boolean isValidNonce(String nonce, String recipientId) {
        if (nonce == null || nonce.isEmpty()) {
            return false;
        }

        String key = buildKey(nonce, recipientId);

        if (useRedis) {
            try {
                Boolean result = redisTemplate.opsForValue()
                        .setIfAbsent(key, System.currentTimeMillis(), Duration.ofSeconds(ttlSeconds));
                return result != null && result;
            } catch (Exception e) {
                log.error("[SECURITY_RISK] Redis error during nonce validation: {}", e.getMessage());
                if (strictMode) {
                    throw new SecurityException("Replay protection unavailable (Redis down) and strict mode is enabled.");
                }
                log.warn("[FALLBACK] Falling back to local cache. Nonce consistency NOT guaranteed across nodes!");
                useRedis = false;
            }
        }

        return localModeIsValid(key);
    }

    private boolean localModeIsValid(String key) {
        if (localCache.size() >= maxCacheSize) {
            cleanupLocal();
        }
        Long previous = localCache.putIfAbsent(key, System.currentTimeMillis());
        return previous == null;
    }

    public boolean validateTimestamp(long timestamp, long windowSeconds) {
        long now = System.currentTimeMillis();
        long diff = Math.abs(now - timestamp);
        return diff <= windowSeconds * 1000;
    }

    public boolean validateExpiry(long timestamp, long expirySeconds) {
        long now = System.currentTimeMillis();
        return (now - timestamp) <= expirySeconds * 1000;
    }

    public void markAsUsed(String nonce, String recipientId) {
        if (nonce == null || nonce.isEmpty()) {
            return;
        }

        String key = buildKey(nonce, recipientId);

        if (useRedis) {
            try {
                redisTemplate.opsForValue().set(key, System.currentTimeMillis(), Duration.ofSeconds(ttlSeconds));
            } catch (Exception e) {
                log.warn("Redis error in markAsUsed: {}", e.getMessage());
                localCache.put(key, System.currentTimeMillis());
            }
        } else {
            localCache.put(key, System.currentTimeMillis());
        }
    }

    public void clear() {
        if (useRedis) {
            try {
                deleteKeysWithScan(NONCE_PREFIX + "*");
            } catch (Exception e) {
                log.warn("Redis error in clear: {}", e.getMessage());
            }
        }
        localCache.clear();
    }

    private void deleteKeysWithScan(String pattern) {
        var scanOptions = ScanOptions.scanOptions().match(pattern).count(1000).build();
        try (var cursor = redisTemplate.scan(scanOptions)) {
            while (cursor.hasNext()) {
                redisTemplate.delete(cursor.next());
            }
        }
    }

    public void cleanup() {
        cleanupLocal();
        checkRedisConnection();
    }

    private void cleanupLocal() {
        long cutoff = System.currentTimeMillis() - (ttlSeconds * 1000);
        localCache.entrySet().removeIf(entry -> entry.getValue() < cutoff);
    }

    public int getCacheSize() {
        if (useRedis) {
            try {
                return countKeysWithScan(NONCE_PREFIX + "*");
            } catch (Exception e) {
                log.warn("Redis error getting cache size: {}", e.getMessage());
                useRedis = false;
            }
        }
        return localCache.size();
    }

    private int countKeysWithScan(String pattern) {
        int count = 0;
        var scanOptions = ScanOptions.scanOptions().match(pattern).count(1000).build();
        try (var cursor = redisTemplate.scan(scanOptions)) {
            while (cursor.hasNext()) {
                cursor.next();
                count++;
            }
        }
        return count;
    }

    private void checkRedisConnection() {
        if (!useRedis && redisTemplate != null) {
            try {
                redisTemplate.opsForValue().get("pgp:healthcheck");
                useRedis = true;
                reconnectAttempts.set(0);
                log.info("Redis connection recovered - switching from local cache to Redis");
            } catch (Exception e) {
                log.debug("Redis still unavailable: {}", e.getMessage());
            }
        }
    }

    @Scheduled(fixedRate = 30000)  // Check every 30 seconds
    public void periodicRedisHealthCheck() {
        if (!useRedis && redisTemplate != null) {
            int attempts = reconnectAttempts.incrementAndGet();
            if (attempts <= MAX_RECONNECT_ATTEMPTS) {
                log.info("Periodic Redis reconnection attempt {}/{}", attempts, MAX_RECONNECT_ATTEMPTS);
                checkRedisConnection();
            } else if (attempts == MAX_RECONNECT_ATTEMPTS + 1) {
                log.warn("Max reconnection attempts reached ({}) - will retry in next cycle", MAX_RECONNECT_ATTEMPTS);
                reconnectAttempts.set(0);  // Reset to allow retry
            }
        }
    }

    public boolean isRedisAvailable() {
        return useRedis;
    }

    public String getCacheMode() {
        return useRedis ? "REDIS" : "LOCAL";
    }

    private String buildKey(String nonce, String recipientId) {
        return NONCE_PREFIX + nonce + "|" + recipientId;
    }

    public static class ValidationResult {
        public final boolean valid;
        public final String error;

        public ValidationResult(boolean valid, String error) {
            this.valid = valid;
            this.error = error;
        }

        public static ValidationResult success() {
            return new ValidationResult(true, null);
        }

        public static ValidationResult failure(String error) {
            return new ValidationResult(false, error);
        }
    }

    public ValidationResult validateEnvelope(String nonce, String correlationId, String recipientId, long timestamp) {
        if (nonce == null || nonce.isEmpty()) {
            return ValidationResult.failure("Missing nonce");
        }

        if (!isValidNonce(nonce, recipientId)) {
            return ValidationResult.failure("Nonce already used or invalid");
        }

        if (correlationId == null || correlationId.isEmpty()) {
            return ValidationResult.failure("Missing correlation ID");
        }

        if (!validateTimestamp(timestamp, 300)) {
            return ValidationResult.failure("Timestamp outside allowable window");
        }

        return ValidationResult.success();
    }
}