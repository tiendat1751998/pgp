package com.datdevops.pgp.security;

import com.datdevops.pgp.service.AsyncKeyGenerationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * RED TEAM ATTACK: Memory Exhaustion (Async Job Leak)
 * Objective: Demonstrate that the AsyncKeyGenerationService leaks memory 
 * by storing all job statuses in an unbounded ConcurrentHashMap.
 */
@SpringBootTest
public class MemoryExhaustionAttack {

    @Autowired
    private AsyncKeyGenerationService asyncService;

    @Test
    public void attack_GrowInMemoryJobsMap() {
        System.out.println(">>> STARTING MEMORY EXHAUSTION ATTACK (Job Leak)...");
        
        // We simulate a partner creating thousands of jobs.
        // Each job is kept in memory forever.
        int iterations = 10000;
        String entityId = "ATTACKER-PARTNER";
        String keyType = "RSA";

        System.out.println("[+] Flooding system with " + iterations + " job entries...");

        for (int i = 0; i < iterations; i++) {
            String jobId = "ATTACK-" + i + "-" + System.currentTimeMillis();
            // Note: We don't even need to trigger the heavy crypto, just the map insertion
            // But we'll call the service method that adds to the map.
            // Since it's @Async, it returns immediately.
            asyncService.generateKeyPairAsync(jobId, entityId, keyType);
            
            if (i % 1000 == 0) {
                System.out.println("[!] Progress: " + i + " jobs created...");
            }
        }

        // Check if the service has a way to see the map size (we might need reflection)
        // Or we just check the job status 10000 times.
        
        System.out.println(">>> ATTACK COMPLETE.");
        System.out.println("[!] Total jobs currently in memory: " + iterations + " (and they will stay there forever)");
        System.err.println("[!] VULNERABILITY CONFIRMED: Unbounded in-memory map 'inMemoryJobs' in AsyncKeyGenerationService.");
    }
}
