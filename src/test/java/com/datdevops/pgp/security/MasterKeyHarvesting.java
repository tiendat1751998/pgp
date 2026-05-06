package com.datdevops.pgp.security;

import com.datdevops.pgp.service.SecretEncryptionService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.lang.reflect.Field;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * RED TEAM ATTACK: Master Key Harvesting
 * Objective: Demonstrate that sensitive master keys can be extracted from memory 
 * if stored as immutable Strings or accessible fields.
 */
@SpringBootTest
public class MasterKeyHarvesting {

    @Autowired
    private SecretEncryptionService secretEncryptionService;

    @Test
    public void attack_ExfiltrateMasterKey() throws Exception {
        System.out.println(">>> STARTING MASTER KEY HARVESTING...");

        // Technique 1: Reflection on Service Fields
        // In a real attack, if a hacker gains execution context (via RCE), 
        // they can reflect into Spring beans.
        
        Class<?> clazz = secretEncryptionService.getClass();
        // Handle Spring CGLIB Proxy
        if (clazz.getName().contains("$$SpringCGLIB")) {
            clazz = clazz.getSuperclass();
        }

        Field keyField = null;
        try {
            keyField = clazz.getDeclaredField("masterKey");
            keyField.setAccessible(true);
        } catch (NoSuchFieldException e) {
            System.err.println("[-] Field 'masterKey' not found (Maybe it's obfuscated?)");
        }

        if (keyField != null) {
            Object keyValue = keyField.get(secretEncryptionService);
            System.out.println("[+] HARVESTED MASTER KEY (via Reflection): " + keyValue);
            
            if (keyValue instanceof String) {
                System.err.println("[!] VULNERABILITY: Master key is stored as a String (Immutable/Heap-polluting)");
            }
        }

        // Technique 2: Heap Entropy Analysis Simulation
        // We simulate what an attacker would see in a heap dump
        String encryptedData = secretEncryptionService.encrypt("TOP_SECRET_PAYLOAD");
        assertNotNull(encryptedData);

        System.out.println(">>> HARVESTING COMPLETE.");
    }
}
