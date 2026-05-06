package com.datdevops.pgp.service;

import org.redisson.RedissonRedLock;
import org.redisson.api.RLock;
import org.redisson.api.RedissonClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Collections;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

@Service
public class DistributedLockService {

    private static final Logger log = LoggerFactory.getLogger(DistributedLockService.class);
    private static final String LOCK_PREFIX = "lock:keystore:";
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration DEFAULT_LEASE_TIME = Duration.ofSeconds(30);
    private static final int MAX_RETRY_ATTEMPTS = 3;
    private static final long INITIAL_BACKOFF_MS = 50;

    private final StringRedisTemplate redisTemplate;
    private final RedissonClient redissonClient;
    private final String lockOwnerId;

    public DistributedLockService(
            @Autowired(required = false) StringRedisTemplate redisTemplate,
            @Autowired(required = false) RedissonClient redissonClient) {
        this.redisTemplate = redisTemplate;
        this.redissonClient = redissonClient;
        this.lockOwnerId = UUID.randomUUID().toString();
        log.info("DistributedLockService initialized with Redisson: {}", redissonClient != null);
    }

    public <T> T executeWithLock(String resourceId, Duration timeout, Duration leaseTime, Supplier<T> action) {
        String lockKey = LOCK_PREFIX + resourceId;

        if (redissonClient != null) {
            return executeWithRedissonLock(resourceId, lockKey, timeout, action);
        } else if (redisTemplate != null) {
            return executeWithRedisTemplateLock(resourceId, lockKey, timeout, leaseTime, action);
        } else {
            log.warn("No Redis client available, executing without lock");
            return action.get();
        }
    }

    private <T> T executeWithRedissonLock(String resourceId, String lockKey, Duration timeout, Supplier<T> action) {
        RLock lock = redissonClient.getLock(lockKey);
        try {
            // tryLock with only waitTime enables the Redisson Watchdog (auto-renewal)
            // This is perfect for long-running stream operations.
            boolean acquired = lock.tryLock(timeout.toMillis(), TimeUnit.MILLISECONDS);
            
            if (!acquired) {
                log.warn("[LOCK_TIMEOUT] Could not acquire Redisson lock: {} after {}ms", resourceId, timeout.toMillis());
                throw new IllegalStateException("Resource is currently busy: " + resourceId);
            }
            
            log.debug("Redisson lock acquired with Watchdog for: {}", resourceId);
            return action.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Lock acquisition interrupted for: " + resourceId, e);
        } finally {
            // Only unlock if we are the owner. 
            // Watchdog will have stopped if the thread died or we finished.
            if (lock.isHeldByCurrentThread()) {
                lock.unlock();
                log.debug("Redisson lock released for: {}", resourceId);
            }
        }
    }

    private <T> T executeWithRedisTemplateLock(String resourceId, String lockKey, Duration timeout, Duration leaseTime, Supplier<T> action) {
        String requestId = lockOwnerId + ":" + UUID.randomUUID().toString();

        int attempt = 0;
        long backoffMs = INITIAL_BACKOFF_MS;

        while (attempt < MAX_RETRY_ATTEMPTS) {
            boolean acquired = tryAcquire(lockKey, requestId, leaseTime);
            if (acquired) {
                try {
                    log.debug("Redis lock acquired for resource: {} on attempt {}", resourceId, attempt + 1);
                    return action.get();
                } catch (Exception e) {
                    log.error("Error executing locked action for resource: {}", resourceId, e);
                    throw e;
                } finally {
                    releaseLock(lockKey, requestId);
                }
            }

            attempt++;
            if (attempt < MAX_RETRY_ATTEMPTS) {
                try {
                    Thread.sleep(backoffMs);
                    backoffMs *= 2;
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("Lock acquisition interrupted for resource: " + resourceId);
                }
            }
        }

        throw new IllegalStateException("Failed to acquire lock for resource: " + resourceId + " after " + MAX_RETRY_ATTEMPTS + " attempts");
    }

    public <T> T executeWithLock(String resourceId, Supplier<T> action) {
        return executeWithLock(resourceId, DEFAULT_TIMEOUT, DEFAULT_LEASE_TIME, action);
    }

    private boolean tryAcquire(String lockKey, String requestId, Duration leaseTime) {
        if (redisTemplate == null) return false;
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
        if (redisTemplate == null) return;
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
        if (redissonClient != null) {
            RLock lock = redissonClient.getLock(LOCK_PREFIX + resourceId);
            try {
                return lock.tryLock(0, leaseTime.toMillis(), TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }

        String lockKey = LOCK_PREFIX + resourceId;
        String requestId = lockOwnerId + ":" + UUID.randomUUID().toString();
        return tryAcquire(lockKey, requestId, leaseTime);
    }

    public boolean unlock(String resourceId) {
        String lockKey = LOCK_PREFIX + resourceId;

        if (redissonClient != null) {
            RLock lock = redissonClient.getLock(lockKey);
            try {
                if (lock.isHeldByCurrentThread()) {
                    lock.unlock();
                    log.debug("Redisson lock released for resource: {}", resourceId);
                    return true;
                }
                return false;
            } catch (Exception e) {
                log.warn("Failed to unlock Redisson resource: {}. Error: {}", resourceId, e.getMessage());
                return false;
            }
        }

        if (redisTemplate == null) return false;
        String requestIdPrefix = lockOwnerId + ":";
        try {
            String script = "local val = redis.call('get', KEYS[1]) " +
                    "if val and string.sub(val, 1, #ARGV[1]) == ARGV[1] then " +
                    "  return redis.call('del', KEYS[1]) " +
                    "else return 0 end";
            DefaultRedisScript<Long> redisScript = new DefaultRedisScript<>(script, Long.class);
            Long result = redisTemplate.execute(redisScript, Collections.singletonList(lockKey), requestIdPrefix);
            boolean released = result != null && result > 0;
            log.debug("Lock release for {}: {}", resourceId, released ? "success" : "not-owner");
            return released;
        } catch (Exception e) {
            log.warn("Failed to unlock resource: {}. Error: {}", resourceId, e.getMessage());
            return false;
        }
    }

    public <T> T executeWithDynamicLease(String resourceId, Duration expectedDuration, Supplier<T> action) {
        Duration leaseTime = expectedDuration.plus(Duration.ofSeconds(30));
        return executeWithLock(resourceId, expectedDuration, leaseTime, action);
    }
}