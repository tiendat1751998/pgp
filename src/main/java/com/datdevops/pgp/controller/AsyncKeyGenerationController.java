package com.datdevops.pgp.controller;

import com.datdevops.pgp.dto.response.ApiResponse;
import com.datdevops.pgp.dto.response.AsyncJobResponse;
import com.datdevops.pgp.entity.AsyncJob;
import com.datdevops.pgp.security.SenderContext;
import com.datdevops.pgp.service.AsyncKeyGenerationService;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Key generation controller.
 * Identity is always derived from mTLS certificate (SenderContext).
 * Partners can only generate keys for themselves.
 */
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
    public ResponseEntity<ApiResponse<AsyncJobResponse>> generateKeyPairAsync(
            @RequestParam(defaultValue = "ALL") String keyType) {

        String entityId = requireAuthentication();

        String jobId = asyncKeyGenerationService.generateJobId();
        log.info("[KEYGEN] Starting async key generation: jobId={}, entityId={}, keyType={}", jobId, entityId, keyType);

        asyncKeyGenerationService.generateKeyPairAsync(jobId, entityId, keyType);
        keyGenCounter.increment();

        AsyncJobResponse response = AsyncJobResponse.processing(jobId, entityId, keyType);
        return ResponseEntity.accepted().body(ApiResponse.success("Key generation started", response));
    }

    @GetMapping("/status/{jobId}")
    public ResponseEntity<ApiResponse<AsyncJobResponse>> getJobStatus(@PathVariable String jobId) {
        requireAuthentication();

        AsyncJob job = asyncKeyGenerationService.getJobStatus(jobId);
        if (job == null) {
            return ResponseEntity.notFound().build();
        }

        // Verify the job belongs to the authenticated sender
        String authenticatedId = SenderContext.getSenderId();
        if (!authenticatedId.equals(job.getEntityId())) {
            log.warn("[SECURITY] Job ownership violation: authenticated={} jobOwner={}", authenticatedId, job.getEntityId());
            return ResponseEntity.status(403).build();
        }

        AsyncJobResponse response = AsyncJobResponse.fromEntity(job);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    private String requireAuthentication() {
        String senderId = SenderContext.getSenderId();
        if (senderId == null || senderId.isBlank()) {
            throw new SecurityException("Unauthorized: No authenticated identity");
        }
        return senderId;
    }
}