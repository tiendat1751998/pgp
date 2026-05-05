package com.datdevops.pgp.service;

import com.datdevops.pgp.entity.AsyncJob;
import com.datdevops.pgp.repository.AsyncJobRepository;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.AsyncResult;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class AsyncKeyGenerationService {

    private static final Logger log = LoggerFactory.getLogger(AsyncKeyGenerationService.class);

    private final KeyPairGeneratorService keyPairGeneratorService;
    private final RSAKeyPairGeneratorService rsaKeyPairGeneratorService;
    private final KeyRotationService keyRotationService;
    private final AsyncJobRepository asyncJobRepository;
    private final SecretEncryptionService secretEncryptionService;

    private final Map<String, AsyncJob> inMemoryJobs = new ConcurrentHashMap<>();

    public AsyncKeyGenerationService(
            KeyPairGeneratorService keyPairGeneratorService,
            RSAKeyPairGeneratorService rsaKeyPairGeneratorService,
            KeyRotationService keyRotationService,
            AsyncJobRepository asyncJobRepository,
            SecretEncryptionService secretEncryptionService) {
        this.keyPairGeneratorService = keyPairGeneratorService;
        this.rsaKeyPairGeneratorService = rsaKeyPairGeneratorService;
        this.keyRotationService = keyRotationService;
        this.asyncJobRepository = asyncJobRepository;
        this.secretEncryptionService = secretEncryptionService;
    }

    public AsyncKeyGenerationService() {
        this.keyPairGeneratorService = new KeyPairGeneratorService();
        this.rsaKeyPairGeneratorService = new RSAKeyPairGeneratorService();
        this.keyRotationService = null;
        this.asyncJobRepository = null;
        this.secretEncryptionService = null;
    }

    @Async("keyGenExecutor")
    public AsyncResult<AsyncJob> generateKeyPairAsync(String jobId, String entityId, String keyType) {
        log.info("Starting async key generation: jobId={}, entityId={}, keyType={}", jobId, entityId, keyType);

        AsyncJob job = createJob(jobId, entityId, keyType);

        try {
            long startTime = System.currentTimeMillis();

            if ("RSA".equalsIgnoreCase(keyType)) {
                var rsaKeyPair = rsaKeyPairGeneratorService.generateRSAKeyPair();
                String publicKey = rsaKeyPairGeneratorService.getBase64PublicKey(rsaKeyPair);
                String privateKey = rsaKeyPairGeneratorService.getBase64PrivateKey(rsaKeyPair);
                String encryptedPrivateKey = secretEncryptionService != null ?
                    secretEncryptionService.encrypt(privateKey) : privateKey;

                if (keyRotationService != null) {
                    keyRotationService.rotateRSAKey(entityId, publicKey, encryptedPrivateKey);
                    var activeKey = keyRotationService.getActiveKey(entityId, "RSA");
                    activeKey.ifPresent(key -> job.setResult(key.getPublicKey()));
                }
            } else if ("ED25519".equalsIgnoreCase(keyType)) {
                var ed25519KeyPair = keyPairGeneratorService.generateEd25519KeyPair();
                byte[] publicKeyBytes = keyPairGeneratorService.getEd25519PublicKey(ed25519KeyPair).getEncoded();
                byte[] privateKeyBytes = keyPairGeneratorService.getEd25519PrivateKey(ed25519KeyPair).getEncoded();
                String publicKey = Base64.getEncoder().encodeToString(publicKeyBytes);
                String privateKey = Base64.getEncoder().encodeToString(privateKeyBytes);
                String encryptedPrivateKey = secretEncryptionService != null ?
                    secretEncryptionService.encrypt(privateKey) : privateKey;

                if (keyRotationService != null) {
                    keyRotationService.rotateEd25519Key(entityId, publicKey, encryptedPrivateKey);
                    var activeKey = keyRotationService.getActiveKey(entityId, "ED25519");
                    activeKey.ifPresent(key -> job.setResult(key.getPublicKey()));
                }
            } else {
                var ed25519KeyPair = keyPairGeneratorService.generateEd25519KeyPair();
                var rsaKeyPair = rsaKeyPairGeneratorService.generateRSAKeyPair();

                // Security: NEVER store raw private keys in AsyncJob result field.
                // If needed, only store encrypted versions or public keys.
                Map<String, String> publicKeys = Map.of(
                    "ed25519PublicKey", Base64.getEncoder().encodeToString(keyPairGeneratorService.getEd25519PublicKey(ed25519KeyPair).getEncoded()),
                    "rsaPublicKey", rsaKeyPairGeneratorService.getBase64PublicKey(rsaKeyPair)
                );

                job.setResult(new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(publicKeys));
            }

            long duration = System.currentTimeMillis() - startTime;
            job.setStatus("COMPLETED");
            job.setCompletedAt(Instant.now());

            log.info("Async key generation completed: jobId={}, duration={}ms", jobId, duration);

        } catch (Exception e) {
            log.error("Async key generation failed: jobId={}, error={}", jobId, e.getMessage(), e);
            job.setStatus("FAILED");
            job.setErrorMessage(e.getMessage());
            job.setCompletedAt(Instant.now());
        }

        saveJob(job);

        return new AsyncResult<>(job);
    }

    private AsyncJob createJob(String jobId, String entityId, String keyType) {
        AsyncJob job = new AsyncJob(jobId, "KEY_GENERATION", entityId, keyType);
        if (asyncJobRepository != null) {
            asyncJobRepository.save(job);
        }
        inMemoryJobs.put(jobId, job);
        return job;
    }

    private void saveJob(AsyncJob job) {
        if (asyncJobRepository != null) {
            asyncJobRepository.save(job);
        } else {
            inMemoryJobs.put(job.getJobId(), job);
        }
    }

    public AsyncJob getJobStatus(String jobId) {
        if (asyncJobRepository != null) {
            return asyncJobRepository.findById(jobId).orElse(null);
        }
        return inMemoryJobs.get(jobId);
    }

    public String generateJobId() {
        return "KEY-" + System.currentTimeMillis() + "-" + java.util.UUID.randomUUID().toString().substring(0, 8);
    }
}
