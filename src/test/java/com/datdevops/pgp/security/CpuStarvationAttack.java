package com.datdevops.pgp.security;

import com.datdevops.pgp.service.PartnerService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * RED TEAM ATTACK: CPU Starvation (Thread Pool Exhaustion)
 * Objective: Demonstrate that the PartnerService blocks web threads with heavy 
 * RSA cryptography before performing duplicate ID checks, leading to DoS.
 */
@SpringBootTest
public class CpuStarvationAttack {

    @Autowired
    private PartnerService partnerService;

    @Test
    public void attack_ThreadStarvationViaOnboarding() {
        System.out.println(">>> STARTING CPU STARVATION ATTACK...");

        int concurrentRequests = 10;
        ExecutorService executor = Executors.newFixedThreadPool(concurrentRequests);
        List<CompletableFuture<Void>> futures = new ArrayList<>();

        long start = System.currentTimeMillis();

        for (int i = 0; i < concurrentRequests; i++) {
            futures.add(CompletableFuture.runAsync(() -> {
                try {
                    // All threads try to onboard the SAME partner ID simultaneously
                    partnerService.onboardPartner(
                        "ATTACKER_ID", 
                        "Attacker Corp", 
                        "mock_rsa_pub", 
                        "mock_ed_pub"
                    );
                } catch (Exception e) {
                    // Expected to fail with "Partner already exists" or constraint violation
                    // BUT only AFTER wasting 1-2 seconds of CPU time generating RSA keys.
                }
            }, executor));
        }

        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
        long duration = System.currentTimeMillis() - start;

        System.out.println(">>> ATTACK FINISHED.");
        System.out.println("Total time for " + concurrentRequests + " blocked threads: " + duration + " ms");
        
        executor.shutdown();
    }
}
