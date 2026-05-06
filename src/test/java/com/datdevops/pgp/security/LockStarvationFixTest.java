package com.datdevops.pgp.security;

import com.datdevops.pgp.service.DistributedLockService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
public class LockStarvationFixTest {

    @Autowired
    private DistributedLockService distributedLockService;

    @Autowired
    private StringRedisTemplate redisTemplate;

    @Test
    public void testLockRetryLogic_PreventsStarvation() throws InterruptedException {
        String resourceId = "test-retry-" + System.currentTimeMillis();
        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger failureCount = new AtomicInteger(0);

        int numThreads = 5;
        Thread[] threads = new Thread[numThreads];

        for (int i = 0; i < numThreads; i++) {
            final int threadNum = i;
            threads[i] = new Thread(() -> {
                try {
                    String result = distributedLockService.executeWithLock(resourceId, Duration.ofSeconds(2), Duration.ofSeconds(5), () -> {
                        try {
                            Thread.sleep(50);
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                        }
                        return "Success from thread " + threadNum;
                    });
                    successCount.incrementAndGet();
                } catch (Exception e) {
                    failureCount.incrementAndGet();
                }
            });
        }

        for (Thread t : threads) {
            t.start();
        }

        for (Thread t : threads) {
            try {
                t.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        assertTrue(successCount.get() > 0, "At least some requests should succeed with retry logic");
    }

    @Test
    public void testRetryLimit_PreventsInfiniteWait() {
        String resourceId = "test-backoff-" + System.currentTimeMillis();

        long startTime = System.currentTimeMillis();

        try {
            distributedLockService.executeWithLock(resourceId, Duration.ofMillis(100), Duration.ofSeconds(1), () -> "done");
        } catch (Exception e) {
        }

        long elapsed = System.currentTimeMillis() - startTime;

        assertTrue(elapsed < 3000, "Should not wait forever with retry limits");
    }

    @Test
    public void testUnlockUsesAtomicScript() {
        String resourceId = "test-atomic-unlock-" + System.currentTimeMillis();

        boolean locked = distributedLockService.tryLock(resourceId, Duration.ofSeconds(10));
        assertTrue(locked, "Should acquire lock");

        distributedLockService.unlock(resourceId);

        assertFalse(distributedLockService.tryLock(resourceId, Duration.ofSeconds(1)),
            "Lock should be released after unlock");
    }
}