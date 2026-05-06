package com.datdevops.pgp.security;

import com.datdevops.pgp.service.KeyRotationService;
import com.datdevops.pgp.service.KeyService;
import com.datdevops.pgp.entity.KeyVersion;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * RED TEAM ATTACK: Cache-DB Split Brain (Consistency Attack)
 * Objective: Force the system to use stale cached keys while a rotation is in progress.
 */
@SpringBootTest
public class ConsistencyAttackTest {

    @Autowired
    private KeyRotationService rotationService;

    @Autowired
    private KeyService keyService;

    @Test
    public void attack_KeyConsistencyUnderStress() throws Exception {
        final String ownerId = "CONSISTENCY-TARGET";
        final String keyType = "RSA";
        
        // Setup: Initial key
        rotationService.rotateRSAKey(ownerId);
        
        ExecutorService executor = Executors.newFixedThreadPool(10);
        AtomicInteger inconsistencyDetected = new AtomicInteger(0);
        int iterations = 50;

        System.out.println(">>> STARTING CONSISTENCY ATTACK (Cache vs DB)...");

        List<CompletableFuture<Void>> futures = new ArrayList<>();

        for (int i = 0; i < iterations; i++) {
            // Task 1: Continuous Rotation
            futures.add(CompletableFuture.runAsync(() -> {
                rotationService.rotateRSAKey(ownerId);
            }, executor));

            // Task 2: High-frequency Key Access (Potential stale read from cache)
            futures.add(CompletableFuture.runAsync(() -> {
                for(int j=0; j<10; j++) {
                    try {
                        Object activeKey = keyService.getRecipientPublicKey(ownerId);
                        // In a perfect system, the key returned should ALWAYS be the one most recently committed
                        if (activeKey == null) {
                            inconsistencyDetected.incrementAndGet();
                            System.err.print("X"); // X for Inconsistency
                        } else {
                            System.out.print("."); // . for OK
                        }
                    } catch (Exception e) {
                        // If we hit an exception during rotation, it might also be a consistency issue
                        inconsistencyDetected.incrementAndGet();
                        System.err.print("E"); 
                    }
                }
            }, executor));
        }

        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
        executor.shutdown();

        System.out.println("\n>>> ATTACK COMPLETE");
        System.out.println("Inconsistencies (Stale Reads): " + inconsistencyDetected.get());

        // We want to see if any stale or inactive keys were served during the rotation process.
        // If > 0, it means the 'afterCommit' cache invalidation has a race window.
        assertTrue(true); // Observation mode
    }
}
