package com.datdevops.pgp.security;

import com.datdevops.pgp.service.ReplayProtectionService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * RED TEAM ATTACK: Race Nonce
 * Objective: Bypass Replay Protection using high-concurrency race condition.
 */
@SpringBootTest(properties = {
    "app.master-key=this-is-a-very-secure-32char-master-key-!!",
    "app.replay-protection.strict-mode=true"
})
public class ReplayRaceAttack {

    @Autowired
    private ReplayProtectionService replayService;

    @Test
    public void attack_ConcurrentNonceUsage() throws Exception {
        final String sharedNonce = "ATTACK-NONCE-" + UUID.randomUUID();
        final String recipientId = "TARGET-BANK";
        final int concurrentRequests = 100;
        
        ExecutorService executor = Executors.newFixedThreadPool(concurrentRequests);
        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger failureCount = new AtomicInteger(0);
        
        List<CompletableFuture<Void>> futures = new ArrayList<>();

        System.out.println(">>> STARTING RACE ATTACK ON NONCE: " + sharedNonce);
        
        // Prepare all requests simultaneously
        for (int i = 0; i < concurrentRequests; i++) {
            futures.add(CompletableFuture.runAsync(() -> {
                if (replayService.isValidNonce(sharedNonce, recipientId)) {
                    successCount.incrementAndGet();
                    System.out.print("S"); // S for Success
                } else {
                    failureCount.incrementAndGet();
                    System.out.print("F"); // F for Failure
                }
            }, executor));
        }

        // Wait for all to complete
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
        executor.shutdown();

        System.out.println("\n>>> ATTACK COMPLETE");
        System.out.println("Successes (Bypassed): " + successCount.get());
        System.out.println("Failures (Blocked): " + failureCount.get());

        // CRITICAL ASSERTION: In a secure system, ONLY 1 request should EVER succeed.
        // If successCount > 1, the system is VULNERABLE to replay attacks under load.
        assertEquals(1, successCount.get(), "REPLAY ATTACK SUCCESSFUL! Multiple requests with same nonce were accepted.");
    }
}
