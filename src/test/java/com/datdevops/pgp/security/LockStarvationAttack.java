package com.datdevops.pgp.security;

import com.datdevops.pgp.service.DistributedLockService;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

/**
 * RED TEAM ATTACK: Lock Starvation (Immediate Failure)
 * Objective: Demonstrate that the DistributedLockService fails 
 * catastrophically under contention because it lacks a retry mechanism.
 */
public class LockStarvationAttack {

    @Test
    public void attack_LockContentionFailure() {
        System.out.println(">>> STARTING LOCK STARVATION ATTACK...");

        // 1. Setup Mock Redis to simulate a busy lock
        StringRedisTemplate redisTemplate = Mockito.mock(StringRedisTemplate.class);
        ValueOperations<String, String> ops = Mockito.mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(ops);

        // Simulate: First call succeeds (true), all subsequent calls fail (false)
        when(ops.setIfAbsent(anyString(), anyString(), any(Duration.class)))
            .thenReturn(true)  // First thread wins
            .thenReturn(false); // All others lose immediately

        DistributedLockService lockService = new DistributedLockService(redisTemplate);

        int concurrentThreads = 10;
        ExecutorService executor = Executors.newFixedThreadPool(concurrentThreads);
        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger failureCount = new AtomicInteger(0);

        List<CompletableFuture<Void>> futures = new ArrayList<>();

        for (int i = 0; i < concurrentThreads; i++) {
            futures.add(CompletableFuture.runAsync(() -> {
                try {
                    lockService.executeWithLock("shared-resource", () -> {
                        try { Thread.sleep(100); } catch (InterruptedException e) {}
                        return "SUCCESS";
                    });
                    successCount.incrementAndGet();
                } catch (IllegalStateException e) {
                    failureCount.incrementAndGet();
                }
            }, executor));
        }

        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

        System.out.println("[+] Attack Results:");
        System.out.println("    Threads: " + concurrentThreads);
        System.out.println("    Successes: " + successCount.get());
        System.out.println("    Failures (Starved): " + failureCount.get());

        // In a resilient system, failures should be 0 (they should wait and retry)
        // In the current system, failureCount will be concurrentThreads - 1
        assertTrue(failureCount.get() > 0, "System is vulnerable: lock starvation occurred");
        
        System.err.println("[!] VULNERABILITY CONFIRMED: " + failureCount.get() + " requests failed due to lack of lock retry.");
        
        executor.shutdown();
    }
}
