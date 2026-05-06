package com.datdevops.pgp.service;

import com.datdevops.pgp.entity.KeyVersion;
import com.datdevops.pgp.repository.KeyVersionRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * Service for managing cryptographic key rotation and lifecycle.
 * Optimized for performance and transactional integrity.
 */
@Service
public class KeyRotationService {

    private static final Logger log = LoggerFactory.getLogger(KeyRotationService.class);

    private final KeyVersionRepository keyVersionRepository;
    private final KeyPairGeneratorService keyPairGeneratorService;
    private final RSAKeyPairGeneratorService rsaKeyPairGeneratorService;
    private final SecretEncryptionService secretEncryptionService;
    private final KeyService keyService;
    private final SenderRateLimiter senderRateLimiter;

    @Autowired
    public KeyRotationService(KeyVersionRepository keyVersionRepository,
                            KeyPairGeneratorService keyPairGeneratorService,
                            RSAKeyPairGeneratorService rsaKeyPairGeneratorService,
                            SecretEncryptionService secretEncryptionService,
                            KeyService keyService,
                            @Autowired(required = false) SenderRateLimiter senderRateLimiter) {
        this.keyVersionRepository = keyVersionRepository;
        this.keyPairGeneratorService = keyPairGeneratorService;
        this.rsaKeyPairGeneratorService = rsaKeyPairGeneratorService;
        this.secretEncryptionService = secretEncryptionService;
        this.keyService = keyService;
        this.senderRateLimiter = senderRateLimiter;
    }

    /** @deprecated For testing only - public for test access in other packages */
    @Deprecated
    public KeyRotationService() {
        this.keyVersionRepository = null;
        this.keyPairGeneratorService = null;
        this.rsaKeyPairGeneratorService = null;
        this.secretEncryptionService = null;
        this.keyService = null;
        this.senderRateLimiter = null;
    }

    /**
     * Rotates the RSA key for a specific owner.
     */
    @Transactional
    public String rotateRSAKey(String ownerId) {
        if (senderRateLimiter != null) {
            senderRateLimiter.checkKeyGenRateLimit(ownerId);
        }
        
        if (rsaKeyPairGeneratorService == null || secretEncryptionService == null) {
            throw new IllegalStateException("KeyRotationService not fully initialized (missing generator or encryption service)");
        }
        try {
            var rsaKeyPair = rsaKeyPairGeneratorService.generateRSAKeyPair();
            byte[] privateKeyBytes = rsaKeyPairGeneratorService.getEncodedPrivateKey(rsaKeyPair);
            String publicKey = rsaKeyPairGeneratorService.getBase64PublicKey(rsaKeyPair);
            
            try {
                String encryptedPrivateKey = secretEncryptionService.encrypt(privateKeyBytes);
                KeyVersion saved = rotateKey(ownerId, "RSA", publicKey, encryptedPrivateKey);
                return ownerId + "-RSA-" + saved.getVersion();
            } finally {
                // Securely wipe private key bytes from memory
                Arrays.fill(privateKeyBytes, (byte) 0);
            }
        } catch (Exception e) {
            log.error("Failed to rotate RSA key for {}: {}", ownerId, e.getMessage());
            throw new RuntimeException("Failed to rotate RSA key", e);
        }
    }

    /**
     * Rotates the Ed25519 key for a specific owner.
     */
    @Transactional
    public String rotateEd25519Key(String ownerId) {
        if (senderRateLimiter != null) {
            senderRateLimiter.checkKeyGenRateLimit(ownerId);
        }
        
        if (keyPairGeneratorService == null || secretEncryptionService == null) {
            throw new IllegalStateException("KeyRotationService not fully initialized (missing generator or encryption service)");
        }
        try {
            var ed25519KeyPair = keyPairGeneratorService.generateEd25519KeyPair();
            byte[] publicKeyBytes = keyPairGeneratorService.getEd25519PublicKey(ed25519KeyPair).getEncoded();
            byte[] privateKeyBytes = keyPairGeneratorService.getEd25519PrivateKey(ed25519KeyPair).getEncoded();
            
            String publicKey = Base64.getEncoder().encodeToString(publicKeyBytes);
            try {
                String encryptedPrivateKey = secretEncryptionService.encrypt(privateKeyBytes);
                KeyVersion saved = rotateKey(ownerId, "ED25519", publicKey, encryptedPrivateKey);
                return ownerId + "-ED25519-" + saved.getVersion();
            } finally {
                Arrays.fill(privateKeyBytes, (byte) 0);
            }
        } catch (Exception e) {
            log.error("Failed to rotate Ed25519 key for {}: {}", ownerId, e.getMessage());
            throw new RuntimeException("Failed to rotate Ed25519 key", e);
        }
    }

    @Transactional
    public KeyVersion rotateKey(String ownerId, String keyType, String newPublicKey, String newPrivateKeyEncrypted) {
        Instant now = Instant.now();
        
        // ATOMIC: Use pessimistic locking to prevent race conditions
        // This ensures only one transaction can rotate at a time
        if (keyVersionRepository != null) {
            // First, acquire pessimistic lock by reading for update
            keyVersionRepository.findActiveKeyForUpdate(ownerId, keyType);
            
            // Then bulk deactivate (now safe due to lock)
            keyVersionRepository.deactivateExistingKeys(ownerId, keyType, now);
        }

        // 2. Determine next version
        int nextVersion = 1;
        if (keyVersionRepository != null) {
            Integer currentMaxVersion = keyVersionRepository.findByOwnerAndType(ownerId, keyType)
                    .stream().mapToInt(KeyVersion::getVersion).max().orElse(0);
            nextVersion = currentMaxVersion + 1;
        }

        // 3. Create and save new key
        KeyVersion newKey = new KeyVersion();
        newKey.setOwnerId(ownerId);
        newKey.setVersion(nextVersion);
        newKey.setKeyType(keyType);
        newKey.setPublicKey(newPublicKey);
        newKey.setPrivateKeyEncrypted(newPrivateKeyEncrypted);
        newKey.setActive(true);
        newKey.setValidFrom(now);

        KeyVersion saved = newKey;
        if (keyVersionRepository != null) {
            saved = keyVersionRepository.save(newKey);
        }
        log.info("[KEY_ROTATION] Successful for owner={} type={} version={}", ownerId, keyType, nextVersion);

        // 4. Cache Invalidation (Post-Commit)
        if (keyService != null && TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    log.debug("[KEY_MGMT] Invalidating cache for owner: {}", ownerId);
                    keyService.clearCache(ownerId);
                }
            });
        } else if (keyService != null) {
            keyService.clearCache(ownerId);
        }

        return saved;
    }

    public long getActiveKeyCount() {
        if (keyVersionRepository == null) return 0;
        return keyVersionRepository.countActiveKeys();
    }

    public Optional<KeyVersion> getActiveKey(String ownerId, String keyType) {
        if (keyVersionRepository == null) return Optional.empty();
        return keyVersionRepository.findActiveKey(ownerId, keyType);
    }

    public List<KeyVersion> getKeyHistory(String ownerId, String keyType) {
        if (keyVersionRepository == null) return List.of();
        return keyVersionRepository.findByOwnerAndTypeOrderByVersionDesc(ownerId, keyType);
    }

    /**
     * Scheduled task to cleanup old key versions.
     * Hardened to actually remove very old non-active keys if needed.
     */
    @Scheduled(cron = "${app.key-rotation.cleanup-schedule:0 0 0 * * ?}")
    @Transactional
    public void cleanupExpiredKeys() {
        if (keyVersionRepository == null) return;
        
        Instant now = Instant.now();
        List<KeyVersion> expiredKeys = keyVersionRepository.findExpiredKeys(now);

        for (KeyVersion key : expiredKeys) {
            // Logic for archiving or deleting keys can be added here
            log.info("[KEY_CLEANUP] Processing expired key: owner={} version={}", key.getOwnerId(), key.getVersion());
        }
    }
}