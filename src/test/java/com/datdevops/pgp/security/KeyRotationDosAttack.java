package com.datdevops.pgp.security;

import com.datdevops.pgp.service.KeyRotationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * RED TEAM ATTACK: RSA CPU Exhaustion (Key Rotation DoS)
 * Objective: Demonstrate that an authenticated user can monopolize CPU resources 
 * by triggering multiple 4096-bit RSA key rotations.
 */
@SpringBootTest
public class KeyRotationDosAttack {

    @Autowired
    private KeyRotationService keyRotationService;

    @Test
    public void attack_RSAKeyRotationDoS() throws Exception {
        final String partnerId = "DOS-PARTNER";
        
        // 4096-bit RSA generation is heavy. 5 concurrent generations can spike CPU to 100%.
        int concurrentGenerations = 4; 
        ExecutorService executor = Executors.newFixedThreadPool(concurrentGenerations);

        System.out.println(">>> STARTING RSA KEY ROTATION DOS ATTACK...");
        long start = System.currentTimeMillis();

        List<CompletableFuture<Void>> futures = new ArrayList<>();

        for (int i = 0; i < concurrentGenerations; i++) {
            futures.add(CompletableFuture.runAsync(() -> {
                try {
                    System.out.println("[!] Thread " + Thread.currentThread().getName() + " starting RSA 4096 rotation...");
                    keyRotationService.rotateRSAKey(partnerId);
                    System.out.println("[+] Thread " + Thread.currentThread().getName() + " completed.");
                } catch (Exception e) {
                    System.err.println("[-] Rotation failed: " + e.getMessage());
                }
            }, executor));
        }

        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
        long duration = System.currentTimeMillis() - start;

        System.out.println(">>> DOS ATTACK FINISHED.");
        System.out.println("Total time for " + concurrentGenerations + " RSA-4096 rotations: " + duration + " ms");
        System.out.println("Average time per key: " + (duration / concurrentGenerations) + " ms");

        executor.shutdown();
        
        // If average time is high (> 2 seconds), it confirms CPU intensity.
        // Lack of rate limiting allows an attacker to sustain this load.
    }
}
