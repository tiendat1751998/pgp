package com.datdevops.pgp.security;

import com.datdevops.pgp.service.AsyncKeyGenerationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import com.datdevops.pgp.repository.AsyncJobRepository;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * RED TEAM ATTACK: RSA Exhaustion (DoS)
 * Objective: Saturate the Async Thread Pool and CPU using heavy RSA generation tasks.
 */
@SpringBootTest(properties = {
    "app.master-key=this-is-a-very-secure-32char-master-key-!!",
    "logging.level.com.datdevops.pgp.service=INFO"
})
public class RSAExhaustionAttack {

    @Autowired
    private AsyncKeyGenerationService asyncKeyGenService;

    @MockBean
    private AsyncJobRepository asyncJobRepository; // Mock to avoid DB overhead during DoS

    @Test
    public void attack_KeyGenPoolSaturation() throws Exception {
        final int attackVolume = 100; // More than the pool size (20) and queue (500)
        final String entityId = "PARTNER-VICTIM";
        
        AtomicInteger submittedCount = new AtomicInteger(0);
        AtomicInteger errorCount = new AtomicInteger(0);
        List<CompletableFuture<?>> tasks = new ArrayList<>();

        System.out.println(">>> STARTING RSA EXHAUSTION ATTACK - TARGETING ASYNC POOL");
        long start = System.currentTimeMillis();

        for (int i = 0; i < attackVolume; i++) {
            String jobId = "ATTACK-JOB-" + i;
            try {
                // We bypass the controller to hit the service directly for "pure" pool exhaustion
                tasks.add(asyncKeyGenService.generateKeyPairAsync(jobId, entityId, "RSA").completable());
                submittedCount.incrementAndGet();
            } catch (Exception e) {
                errorCount.incrementAndGet();
            }
        }

        System.out.println(">>> All tasks submitted. Waiting for processing...");
        
        // Wait for some tasks to finish to measure impact
        CompletableFuture.runAsync(() -> {
            try {
                CompletableFuture.allOf(tasks.toArray(new CompletableFuture[0])).get(30, TimeUnit.SECONDS);
            } catch (Exception ignored) {}
        }).join();

        long duration = System.currentTimeMillis() - start;
        System.out.println("\n>>> ATTACK SUMMARY");
        System.out.println("Total Requests: " + attackVolume);
        System.out.println("Successfully Queued: " + submittedCount.get());
        System.out.println("Immediate Failures: " + errorCount.get());
        System.out.println("Total Duration: " + duration + "ms");

        // CRITICAL CHECK: Does the system have a way to reject overflow?
        // If the pool has no limit or an infinite queue, this will cause OOM.
    }
}
