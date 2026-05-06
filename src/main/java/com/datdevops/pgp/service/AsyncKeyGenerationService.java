package com.datdevops.pgp.service;

import com.datdevops.pgp.entity.AsyncJob;
import com.datdevops.pgp.repository.AsyncJobRepository;
import com.datdevops.pgp.security.SenderContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.AsyncResult;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Service for asynchronous cryptographic key generation and rotation.
 * Hardened with resource quotas, rate limiting, and safe memory management.
 */
@Service
public class AsyncKeyGenerationService {

    private static final Logger log = LoggerFactory.getLogger(AsyncKeyGenerationService.class);
    private static final int MAX_JOBS_CACHE_SIZE = 10000;
    private static final int JOB_EXPIRATION_MINUTES = 30;
    private static final int MAX_CONCURRENT_JOBS_PER_PARTNER = 10; // Sensible concurrent limit
    private static final int MAX_AUDIT_LOGS_PER_PARTNER = 10000;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // Fix Memory Leak #184: Use Caffeine with expiration instead of unbounded ConcurrentHashMap
    private final Cache<String, AtomicInteger> partnerJobCount;
    private final Cache<String, AtomicInteger> partnerAuditCount;

    private final KeyPairGeneratorService keyPairGeneratorService;
    private final RSAKeyPairGeneratorService rsaKeyPairGeneratorService;
    private final KeyRotationService keyRotationService;
    private final AsyncJobRepository asyncJobRepository;
    private final ObjectMapper objectMapper;
    private final SenderRateLimiter senderRateLimiter;
    private final Cache<String, AsyncJob> jobCache;

    @Autowired
    public AsyncKeyGenerationService(
            KeyPairGeneratorService keyPairGeneratorService,
            RSAKeyPairGeneratorService rsaKeyPairGeneratorService,
            KeyRotationService keyRotationService,
            AsyncJobRepository asyncJobRepository,
            ObjectMapper objectMapper,
            @Autowired(required = false) SenderRateLimiter senderRateLimiter) {
        this.keyPairGeneratorService = keyPairGeneratorService;
        this.rsaKeyPairGeneratorService = rsaKeyPairGeneratorService;
        this.keyRotationService = keyRotationService;
        this.asyncJobRepository = asyncJobRepository;
        this.objectMapper = objectMapper;
        this.senderRateLimiter = senderRateLimiter;

        this.jobCache = Caffeine.newBuilder()
                .maximumSize(MAX_JOBS_CACHE_SIZE)
                .expireAfterWrite(JOB_EXPIRATION_MINUTES, TimeUnit.MINUTES)
                .build();

        this.partnerJobCount = Caffeine.newBuilder()
                .expireAfterAccess(1, TimeUnit.HOURS)
                .build();
                
        this.partnerAuditCount = Caffeine.newBuilder()
                .expireAfterAccess(24, TimeUnit.HOURS)
                .build();
    }

    /**
     * Entry point for async key generation.
     * Hardened: Quota limited and rate limited.
     */
    @Async("keyGenExecutor")
    public AsyncResult<AsyncJob> generateKeyPairAsync(String jobId, String entityId, String keyType) {
        // Fix Logic Bug #185: Track CONCURRENT jobs, not lifetime jobs
        if (!acquireJobSlot(entityId)) {
            AsyncJob job = new AsyncJob(jobId, "KEY_GENERATION", entityId, keyType);
            job.setStatus("FAILED");
            job.setErrorMessage("Partner concurrent job quota exceeded.");
            job.setCompletedAt(Instant.now());
            saveJob(job);
            return new AsyncResult<>(job);
        }

        try {
            if (senderRateLimiter != null) {
                try {
                    senderRateLimiter.checkKeyGenRateLimit(entityId);
                } catch (Exception e) {
                    log.warn("[ASYNC_KEYGEN] Rate limit exceeded for entityId={}", entityId);
                    AsyncJob job = new AsyncJob(jobId, "KEY_GENERATION", entityId, keyType);
                    job.setStatus("FAILED");
                    job.setErrorMessage("Key generation rate limit exceeded. Try again later.");
                    job.setCompletedAt(Instant.now());
                    saveJob(job);
                    return new AsyncResult<>(job);
                }
            }

            log.info("[ASYNC_KEYGEN] Starting task: jobId={}, entityId={}, type={}", jobId, entityId, keyType);
            AsyncJob job = createJob(jobId, entityId, keyType);

            try {
                long startTime = System.currentTimeMillis();

                if (keyRotationService == null) {
                    throw new IllegalStateException("KeyRotationService is not available");
                }

                String resultJson;
                if ("RSA".equalsIgnoreCase(keyType)) {
                    resultJson = keyRotationService.rotateRSAKey(entityId);
                } else if ("ED25519".equalsIgnoreCase(keyType)) {
                    resultJson = keyRotationService.rotateEd25519Key(entityId);
                } else if ("BOTH".equalsIgnoreCase(keyType)) {
                    String rsaResult = keyRotationService.rotateRSAKey(entityId);
                    String edResult = keyRotationService.rotateEd25519Key(entityId);
                    resultJson = objectMapper.writeValueAsString(Map.of("RSA", rsaResult, "ED25519", edResult));
                } else {
                    resultJson = generateCustomKeys(entityId);
                }

                // Security Note #187: Ensure the result returned here only contains PUBLIC metadata, not private keys
                job.setResult(resultJson);
                job.setStatus("COMPLETED");
                job.setCompletedAt(Instant.now());
                log.info("[ASYNC_KEYGEN] Completed: jobId={}, duration={}ms", jobId, (System.currentTimeMillis() - startTime));

            } catch (Exception e) {
                log.error("[ASYNC_KEYGEN] Failed: jobId={}, error={}", jobId, e.getMessage());
                job.setStatus("FAILED");
                job.setErrorMessage(e.getMessage());
                job.setCompletedAt(Instant.now());
            }

            saveJob(job);
            return new AsyncResult<>(job);
        } finally {
            // Fix Logic Bug #185: Always release the slot
            releaseJobSlot(entityId);
        }
    }

    private String generateCustomKeys(String entityId) throws Exception {
        var ed25519KeyPair = keyPairGeneratorService.generateEd25519KeyPair();
        var rsaKeyPair = rsaKeyPairGeneratorService.generateRSAKeyPair();

        Map<String, String> publicKeys = Map.of(
            "ed25519PublicKey", Base64.getEncoder().encodeToString(keyPairGeneratorService.getEd25519PublicKey(ed25519KeyPair).getEncoded()),
            "rsaPublicKey", rsaKeyPairGeneratorService.getBase64PublicKey(rsaKeyPair)
        );

        return objectMapper.writeValueAsString(publicKeys);
    }

    private AsyncJob createJob(String jobId, String entityId, String keyType) {
        AsyncJob job = new AsyncJob(jobId, "KEY_GENERATION", entityId, keyType);
        job.setStatus("PROCESSING");
        job.setCreatedAt(Instant.now());

        if (asyncJobRepository != null) {
            asyncJobRepository.save(job);
        }
        jobCache.put(jobId, job);
        return job;
    }

    private void saveJob(AsyncJob job) {
        if (asyncJobRepository != null) {
            asyncJobRepository.save(job);
        }
        jobCache.put(job.getJobId(), job);
    }

    public AsyncJob getJobStatus(String jobId) {
        String callerId = SenderContext.getSenderId();

        AsyncJob job = jobCache.getIfPresent(jobId);
        if (job == null && asyncJobRepository != null) {
            job = asyncJobRepository.findById(jobId).orElse(null);
        }

        if (job != null && callerId != null && !callerId.equals(job.getEntityId())) {
            log.warn("[SECURITY] Job IDOR attempt: {} tried to access job of {}", callerId, job.getEntityId());
            return null;
        }

        return job;
    }

    public String generateJobId() {
        byte[] randomBytes = new byte[16];
        SECURE_RANDOM.nextBytes(randomBytes);
        return "KEY-" + System.currentTimeMillis() + "-" + Base64.getEncoder().encodeToString(randomBytes).substring(0, 8);
    }

    private boolean acquireJobSlot(String entityId) {
        AtomicInteger count = partnerJobCount.get(entityId, k -> new AtomicInteger(0));
        if (count.get() >= MAX_CONCURRENT_JOBS_PER_PARTNER) {
            log.warn("[QUOTA] Partner {} reached concurrent job limit", entityId);
            return false;
        }
        count.incrementAndGet();
        return true;
    }

    private void releaseJobSlot(String entityId) {
        AtomicInteger count = partnerJobCount.getIfPresent(entityId);
        if (count != null) {
            count.decrementAndGet();
        }
    }

    public boolean checkPartnerAuditQuota(String entityId) {
        AtomicInteger count = partnerAuditCount.get(entityId, k -> new AtomicInteger(0));
        if (count.get() >= MAX_AUDIT_LOGS_PER_PARTNER) {
            return false;
        }
        count.incrementAndGet();
        return true;
    }
}
