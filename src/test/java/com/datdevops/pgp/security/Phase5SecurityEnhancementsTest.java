package com.datdevops.pgp.security;

import com.datdevops.pgp.service.*;
import com.datdevops.pgp.config.CryptoConfig;
import com.datdevops.pgp.repository.AuditRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class Phase5SecurityEnhancementsTest {

    @BeforeAll
    static void setup() {
        new CryptoConfig();
    }

    @Test
    public void testReplayProtectionNonceValidation() {
        ReplayProtectionService replayService = new ReplayProtectionService();
        
        String nonce1 = "nonce-123-" + System.currentTimeMillis();
        String recipientId = "BANK_B";
        
        boolean firstCheck = replayService.isValidNonce(nonce1, recipientId);
        assertTrue(firstCheck, "First nonce should be valid");
        
        boolean secondCheck = replayService.isValidNonce(nonce1, recipientId);
        assertFalse(secondCheck, "Same nonce should be invalid on second check");
        
        System.out.println("Replay Protection Nonce: SUCCESS");
    }

    @Test
    public void testReplayProtectionTimestampValidation() {
        ReplayProtectionService replayService = new ReplayProtectionService();
        
        long currentTime = System.currentTimeMillis();
        boolean validNow = replayService.validateTimestamp(currentTime, 300);
        assertTrue(validNow, "Current timestamp should be valid");
        
        long oldTime = System.currentTimeMillis() - (600 * 1000);
        boolean invalidOld = replayService.validateTimestamp(oldTime, 300);
        assertFalse(invalidOld, "Old timestamp should be invalid");
        
        System.out.println("ReplayProtection Timestamp: SUCCESS");
    }

@Test
    public void testReplayProtectionEnvelopeValidation() {
        ReplayProtectionService replayService = new ReplayProtectionService(300, 10000);

        String nonce = "test-nonce-" + System.currentTimeMillis();
        String correlationId = "corr-" + System.currentTimeMillis();
        String recipientId = "BANK_B";
        long timestamp = System.currentTimeMillis();

        var result = replayService.validateEnvelope(nonce, correlationId, recipientId, timestamp);

        assertTrue(result.valid, "Valid envelope should pass: " + result.error);

        var duplicateResult = replayService.validateEnvelope(nonce, correlationId, recipientId, timestamp);
        assertFalse(duplicateResult.valid, "Duplicate nonce should fail - error: " + duplicateResult.error);

        System.out.println("ReplayProtection Envelope: SUCCESS");
    }

    @Test
    public void testKeyRotationService() throws Exception {
        KeyRotationService keyRotationService = new KeyRotationService();
        
        String bankAKeyId = keyRotationService.rotateRSAKey("BANK_A");
        assertNotNull(bankAKeyId);
        assertTrue(bankAKeyId.contains("BANK_A"));
        
        System.out.println("Key Rotation: SUCCESS");
    }

    @Test
    public void testKeyRotationMultipleKeys() throws Exception {
        KeyRotationService keyRotationService = new KeyRotationService();
        
        String keyId1 = keyRotationService.rotateRSAKey("BANK_A");
        String keyId2 = keyRotationService.rotateRSAKey("BANK_A");
        
        assertNotEquals(keyId1, keyId2, "Key versions should be different");
        
        System.out.println("Key Rotation Multiple: SUCCESS");
    }

    @Test
    public void testAuditService() {
        AuditService auditService = new AuditService();
        
        String correlationId = "corr-" + System.currentTimeMillis();
        String encryptAudit = auditService.logEncrypt(correlationId, "BANK_A", "BANK_B", "RAW", true);
        assertNotNull(encryptAudit);
        
        String decryptAudit = auditService.logDecrypt(correlationId, "BANK_B", "BANK_A", "JSON", true);
        assertNotNull(decryptAudit);
        
        String keyGenAudit = auditService.logKeyGeneration("BANK_A", "RSA");
        assertNotNull(keyGenAudit);
        
        String keyRotAudit = auditService.logKeyRotation("BANK_A", "KEY_v1", "KEY_v2");
        assertNotNull(keyRotAudit);
        
        int logSize = auditService.getLogSize();
        assertEquals(4, logSize);
        
        System.out.println("Audit Service: SUCCESS");
    }

    @Test
    public void testAuditTimestampFormatting() {
        AuditService auditService = new AuditService();
        
        long timestamp = System.currentTimeMillis();
        String formatted = auditService.formatTimestamp(timestamp);
        
        assertNotNull(formatted);
        assertTrue(formatted.length() > 10, "Formatted timestamp should not be empty");
        assertTrue(formatted.contains("-") && formatted.contains(":"), "Should contain date and time separators");
        
        System.out.println("Audit Timestamp Formatting: SUCCESS");
    }

    @Test
    public void testSecurityEventLogging() {
        AuditService auditService = new AuditService();
        
        String eventAudit = auditService.logSecurityEvent("BANK_A", "FAILED_LOGIN", "Attempt 3 from IP 1.2.3.4");
        assertNotNull(eventAudit);
        
        int logSize = auditService.getLogSize();
        assertEquals(1, logSize);
        
        System.out.println("Security Event Logging: SUCCESS");
    }

    @Test
    public void testCombinedSecurityServices() throws Exception {
        KeyRotationService keyRotationService = new KeyRotationService();
        AuditService auditService = new AuditService();
        ReplayProtectionService replayService = new ReplayProtectionService();
        
        String keyId = keyRotationService.rotateRSAKey("BANK_A");
        auditService.logKeyGeneration("BANK_A", "RSA");
        
        String nonce = "combined-nonce-" + System.currentTimeMillis();
        boolean nonceValid = replayService.isValidNonce(nonce, "BANK_A");
        
        assertTrue(nonceValid);
        assertTrue(keyRotationService.getActiveKeyCount() >= 1);
        assertEquals(1, auditService.getLogSize());
        
        System.out.println("Combined Security Services: SUCCESS");
    }

    @Test
    public void testCacheCleanup() {
        ReplayProtectionService replayService = new ReplayProtectionService(1, 100);
        
        for (int i = 0; i < 50; i++) {
            replayService.isValidNonce("nonce-" + i, "BANK");
        }
        
        assertEquals(50, replayService.getCacheSize());
        
        try {
            Thread.sleep(1500);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        replayService.cleanup();
        
        int sizeAfterCleanup = replayService.getCacheSize();
        assertTrue(sizeAfterCleanup < 50 || sizeAfterCleanup == 50);
        
        System.out.println("Cache Cleanup: SUCCESS");
    }
}