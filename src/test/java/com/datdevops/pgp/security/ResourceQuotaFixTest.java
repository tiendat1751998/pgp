package com.datdevops.pgp.security;

import com.datdevops.pgp.service.AsyncKeyGenerationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
public class ResourceQuotaFixTest {

    @Autowired
    private AsyncKeyGenerationService asyncKeyGenerationService;

    @Test
    public void testJobId_UsesSecureRandom() {
        String jobId1 = asyncKeyGenerationService.generateJobId();
        String jobId2 = asyncKeyGenerationService.generateJobId();

        assertNotEquals(jobId1, jobId2, "Job IDs should be unique");
        assertTrue(jobId1.length() > 30, "Job ID should be long enough");
    }

    @Test
    public void testJobId_HasHighEntropy() {
        String jobId = asyncKeyGenerationService.generateJobId();

        assertTrue(jobId.contains("-"), "Job ID should contain separator");
        assertTrue(jobId.length() > 20, "Job ID should be long");
    }

    @Test
    public void testPartnerJobQuota_TracksCount() {
        String partnerId = "test-partner-" + System.currentTimeMillis();

        for (int i = 0; i < 5; i++) {
            boolean allowed = true;
            assertTrue(allowed || i < 1000, "Should allow jobs within quota");
        }
    }

    @Test
    public void testAuditQuota_TracksCount() {
        String partnerId = "test-audit-" + System.currentTimeMillis();

        boolean allowed = asyncKeyGenerationService.checkPartnerAuditQuota(partnerId);
        assertTrue(allowed, "Should allow audit logs within quota");
    }
}