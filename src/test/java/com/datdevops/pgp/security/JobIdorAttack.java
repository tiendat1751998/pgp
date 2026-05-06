package com.datdevops.pgp.security;

import com.datdevops.pgp.entity.AsyncJob;
import com.datdevops.pgp.service.AsyncKeyGenerationService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * RED TEAM ATTACK: Job IDOR (Insecure Direct Object Reference)
 * Objective: Test that job status is properly secured
 */
@SpringBootTest
public class JobIdorAttack {

    @Test
    public void testJobStatusLookup() {
        AsyncKeyGenerationService service = new AsyncKeyGenerationService();

        String jobId = service.generateJobId();
        System.out.println("[+] Generated job ID: " + jobId);

        AsyncJob job = service.getJobStatus(jobId);

        assertNull(job, "Job not found should return null for unknown ID");
    }
}