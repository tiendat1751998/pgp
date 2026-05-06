package com.datdevops.pgp.security;

import com.datdevops.pgp.service.SecretEncryptionService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * RED TEAM ATTACK: Memory Harvesting
 * Objective: Audit the heap memory for leaked sensitive strings after encryption.
 */
@SpringBootTest(properties = {
    "app.master-key=this-is-a-very-secure-32char-master-key-!!"
})
public class MemoryHarvestingAttack {

    @Autowired
    private SecretEncryptionService encryptionService;

    @Test
    public void attack_HeapAuditForSecrets() throws Exception {
        // The secret we are trying to "find" in memory later
        final String sensitiveData = "STOLEN-CREDIT-CARD-1234-5678-9012";
        
        System.out.println(">>> STARTING MEMORY HARVESTING ATTACK");
        
        // 1. Perform a large number of encryptions to scatter the string in heap
        List<String> results = new ArrayList<>();
        for (int i = 0; i < 500; i++) {
            results.add(encryptionService.encrypt(sensitiveData));
        }

        // 2. Clear references to encourage GC but strings might linger in pool or buffers
        results.clear();
        
        // 3. Trigger manual GC to see if data survives (simulating an attacker dumping heap)
        System.gc();
        Thread.sleep(1000);
        System.gc();

        System.out.println(">>> Encryptions complete. Heap is now 'dirty' with potential fragments.");
        System.out.println(">>> ACTION REQUIRED: Use 'jmap -dump:live,format=b,file=heap.bin <pid>' to audit.");
        
        // This test "passes" if it completes, but the real audit happens outside via heap analysis tools.
        assertTrue(true);
    }
}
