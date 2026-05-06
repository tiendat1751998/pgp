package com.datdevops.pgp.security;

import org.junit.jupiter.api.Test;
import java.io.File;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * RED TEAM ATTACK: Insecure Log Location
 * Objective: Demonstrate that storing logs in the system temporary directory 
 * exposes sensitive audit data to other users on the system and risks data loss.
 */
public class InsecureLogLocationAttack {

    @Test
    public void attack_CheckLogLocationSecurity() {
        System.out.println(">>> STARTING INSECURE LOG LOCATION AUDIT...");

        // Simulated check of the log property from logback.xml
        String logRoot = System.getProperty("java.io.tmpdir") + "/pgp/logs";
        File logDir = new File(logRoot);

        System.out.println("[+] Current Log Root: " + logRoot);

        // 1. Check if it's in a shared temporary directory
        boolean isInTmp = logRoot.contains("tmp") || logRoot.contains("TEMP");
        
        if (isInTmp) {
            System.err.println("[!] VULNERABILITY CONFIRMED: Logs are stored in a VOLATILE and potentially SHARED directory!");
            System.err.println("    - Risk 1: Audit Data Loss on system reboot.");
            System.err.println("    - Risk 2: Information Leakage to other local users.");
        }

        assertFalse(isInTmp, "Logs MUST NOT be stored in temporary directories for production systems.");
    }
}
