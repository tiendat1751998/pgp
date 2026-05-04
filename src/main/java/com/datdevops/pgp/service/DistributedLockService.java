package com.datdevops.pgp.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Collections;
import java.util.UUID;
import java.util.function.Supplier;

@Service
public class DistributedLockService {

    private static final Logger log = LoggerFactory.getLogger(DistributedLockService.class);
    private static final String LOCK_PREFIX = "lock:keystore:";
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration DEFAULTLease_TIME = Duration.ofSeconds(30);

    private final StringRedisTemplate redisTemplate;
    private final String lockOwnerId;

    public DistributedLockService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
        this.lockOwnerId = UUID.randomUUID().toString();
    }

    public <T> T executeWithLock(String resourceId, Duration timeout, Duration leaseTime, Supplier<T> action) {
        String lockKey = LOCK_PREFIX + resourceId;
        String requestId = lockOwnerId + ":" + UUID.randomUUID().toString();

        boolean acquired = tryAcquire(lockKey, requestId, leaseTime);
        if (!acquired) {
            throw new IllegalStateException("Failed to acquire lock for resource: " + resourceId);
        }

        try {
            log.debug("Lock acquired for resource: {}", resourceId);
            return action.get();
        } catch (Exception e) {
            log.error("Error executing locked action for resource: {}", resourceId, e);
            throw e;
        } finally {
            releaseLock(lockKey, requestId);
        }
    }

    public <T> T executeWithLock(String resourceId, Supplier<T> action) {
        return executeWithLock(resourceId, DEFAULT_TIMEOUT, DEFAULTLease_TIME, action);
    }

    private boolean tryAcquire(String lockKey, String requestId, Duration leaseTime) {
        try {
            Boolean result = redisTemplate.opsForValue()
                    .setIfAbsent(lockKey, requestId, leaseTime);
            return Boolean.TRUE.equals(result);
        } catch (Exception e) {
            log.warn("Failed to acquire distributed lock: {}. Error: {}", lockKey, e.getMessage());
            return false;
        }
    }

    private void releaseLock(String lockKey, String requestId) {
        try {
            String script = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end";
            DefaultRedisScript<Long> redisScript = new DefaultRedisScript<>(script, Long.class);
            redisTemplate.execute(redisScript, Collections.singletonList(lockKey), requestId);
            log.debug("Lock released for key: {}", lockKey);
        } catch (Exception e) {
            log.warn("Failed to release distributed lock: {}. Error: {}", lockKey, e.getMessage());
        }
    }

    public boolean tryLock(String resourceId, Duration leaseTime) {
        String lockKey = LOCK_PREFIX + resourceId;
        String requestId = lockOwnerId + ":" + UUID.randomUUID().toString();
        return tryAcquire(lockKey, requestId, leaseTime);
    }

    public void unlock(String resourceId) {
        String lockKey = LOCK_PREFIX + resourceId;
        String requestIdPattern = lockOwnerId + ":*";
        try {
            var keys = redisTemplate.keys(lockKey);
            if (keys != null && !keys.isEmpty()) {
                for (String key : keys) {
                    String value = redisTemplate.opsForValue().get(key);
                    if (value != null && value.startsWith(lockOwnerId)) {
                        redisTemplate.delete(key);
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Failed to unlock resource: {}. Error: {}", resourceId, e.getMessage());
        }
    }
}