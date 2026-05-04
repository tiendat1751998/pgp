package com.datdevops.pgp.controller;

import com.datdevops.pgp.entity.AsyncJob;
import com.datdevops.pgp.service.AsyncKeyGenerationService;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/crypto/keys")
public class AsyncKeyGenerationController {

    private static final Logger log = LoggerFactory.getLogger(AsyncKeyGenerationController.class);

    private final AsyncKeyGenerationService asyncKeyGenerationService;
    private final Counter keyGenCounter;

    public AsyncKeyGenerationController(
            AsyncKeyGenerationService asyncKeyGenerationService,
            MeterRegistry meterRegistry) {
        this.asyncKeyGenerationService = asyncKeyGenerationService;
        this.keyGenCounter = Counter.builder("crypto.keygen.total")
                .tag("type", "async")
                .register(meterRegistry);
    }

    @PostMapping("/generate")
    public ResponseEntity<Map<String, Object>> generateKeyPairAsync(
            @RequestParam String entityId,
            @RequestParam(defaultValue = "ALL") String keyType) {

        String jobId = asyncKeyGenerationService.generateJobId();
        log.info("Starting async key generation: jobId={}, entityId={}, keyType={}", jobId, entityId, keyType);

        asyncKeyGenerationService.generateKeyPairAsync(jobId, entityId, keyType);
        keyGenCounter.increment();

        Map<String, Object> response = new HashMap<>();
        response.put("jobId", jobId);
        response.put("status", "PROCESSING");
        response.put("entityId", entityId);
        response.put("keyType", keyType);
        response.put("message", "Key generation started. Use /status/{jobId} to check progress.");

        return ResponseEntity.accepted().body(response);
    }

    @GetMapping("/status/{jobId}")
    public ResponseEntity<Map<String, Object>> getJobStatus(@PathVariable String jobId) {
        AsyncJob job = asyncKeyGenerationService.getJobStatus(jobId);

        if (job == null) {
            return ResponseEntity.notFound().build();
        }

        Map<String, Object> response = new HashMap<>();
        response.put("jobId", job.getJobId());
        response.put("status", job.getStatus());
        response.put("entityId", job.getEntityId());
        response.put("keyType", job.getKeyType());
        response.put("createdAt", job.getCreatedAt());
        response.put("completedAt", job.getCompletedAt());

        if ("COMPLETED".equals(job.getStatus()) && job.getResult() != null) {
            response.put("result", job.getResult());
        } else if ("FAILED".equals(job.getStatus())) {
            response.put("error", job.getErrorMessage());
        }

        return ResponseEntity.ok(response);
    }

    @GetMapping("/jobs/{entityId}")
    public ResponseEntity<Map<String, Object>> getEntityJobs(@PathVariable String entityId) {
        Map<String, Object> response = new HashMap<>();
        response.put("entityId", entityId);
        response.put("message", "Job history endpoint - implement with AsyncJobRepository query if needed");
        return ResponseEntity.ok(response);
    }
}