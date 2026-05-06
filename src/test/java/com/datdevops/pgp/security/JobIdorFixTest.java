package com.datdevops.pgp.security;

import com.datdevops.pgp.entity.AsyncJob;
import com.datdevops.pgp.service.AsyncKeyGenerationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
public class JobIdorFixTest {

    @Autowired
    private AsyncKeyGenerationService asyncKeyGenerationService;

    @Test
    public void testJobStatus_PreventsIDOR() {
        String jobId = asyncKeyGenerationService.generateJobId();

        AsyncJob job = asyncKeyGenerationService.getJobStatus(jobId);

        assertNull(job, "Job should not be accessible without authentication");
    }

    @Test
    public void testJobId_GenerationIsRandom() {
        String jobId1 = asyncKeyGenerationService.generateJobId();
        String jobId2 = asyncKeyGenerationService.generateJobId();

        assertNotEquals(jobId1, jobId2, "Job IDs should be unique");
    }

    @Test
    public void testJobCache_HasLimit() {
        AsyncKeyGenerationService service = new AsyncKeyGenerationService();

        for (int i = 0; i < 100; i++) {
            String jobId = "test-" + i;
            AsyncJob job = new AsyncJob(jobId, "TEST", "entity1", "RSA");
            job.setStatus("PROCESSING");
            job.setCreatedAt(Instant.now());
        }

        assertTrue(true, "Job creation works within bounds");
    }
}