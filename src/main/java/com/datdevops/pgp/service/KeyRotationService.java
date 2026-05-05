package com.datdevops.pgp.service;

import com.datdevops.pgp.entity.KeyVersion;
import com.datdevops.pgp.repository.KeyVersionRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

@Service
public class KeyRotationService {

    private static final Logger log = LoggerFactory.getLogger(KeyRotationService.class);

    private final KeyVersionRepository keyVersionRepository;
    private final KeyPairGeneratorService keyPairGeneratorService;
    private final RSAKeyPairGeneratorService rsaKeyPairGeneratorService;
    private final SecretEncryptionService secretEncryptionService;
    private final KeyService keyService;

    @org.springframework.beans.factory.annotation.Autowired
    public KeyRotationService(KeyVersionRepository keyVersionRepository,
                            KeyPairGeneratorService keyPairGeneratorService,
                            RSAKeyPairGeneratorService rsaKeyPairGeneratorService,
                            SecretEncryptionService secretEncryptionService,
                            KeyService keyService) {
        this.keyVersionRepository = keyVersionRepository;
        this.keyPairGeneratorService = keyPairGeneratorService;
        this.rsaKeyPairGeneratorService = rsaKeyPairGeneratorService;
        this.secretEncryptionService = secretEncryptionService;
        this.keyService = keyService;
    }

    // Constructor for testing
    @Deprecated
    public KeyRotationService() {
        this.keyVersionRepository = null;
        this.keyPairGeneratorService = null;
        this.rsaKeyPairGeneratorService = null;
        this.secretEncryptionService = null;
        this.keyService = null;
    }

    public String rotateRSAKey(String ownerId) {
        if (rsaKeyPairGeneratorService == null || secretEncryptionService == null) {
            throw new IllegalStateException("Services not initialized for key generation");
        }
        try {
            var rsaKeyPair = rsaKeyPairGeneratorService.generateRSAKeyPair();
            String publicKey = rsaKeyPairGeneratorService.getBase64PublicKey(rsaKeyPair);
            String privateKey = rsaKeyPairGeneratorService.getBase64PrivateKey(rsaKeyPair);
            String encryptedPrivateKey = secretEncryptionService.encrypt(privateKey);
            KeyVersion saved = rotateKey(ownerId, "RSA", publicKey, encryptedPrivateKey);
            return ownerId + "-RSA-" + saved.getVersion();
        } catch (Exception e) {
            throw new RuntimeException("Failed to rotate RSA key", e);
        }
    }

    public String rotateEd25519Key(String ownerId) {
        if (keyPairGeneratorService == null || secretEncryptionService == null) {
            throw new IllegalStateException("Services not initialized for key generation");
        }
        try {
            var ed25519KeyPair = keyPairGeneratorService.generateEd25519KeyPair();
            byte[] publicKeyBytes = keyPairGeneratorService.getEd25519PublicKey(ed25519KeyPair).getEncoded();
            byte[] privateKeyBytes = keyPairGeneratorService.getEd25519PrivateKey(ed25519KeyPair).getEncoded();
            String publicKey = java.util.Base64.getEncoder().encodeToString(publicKeyBytes);
            String privateKey = java.util.Base64.getEncoder().encodeToString(privateKeyBytes);
            String encryptedPrivateKey = secretEncryptionService.encrypt(privateKey);
            KeyVersion saved = rotateKey(ownerId, "ED25519", publicKey, encryptedPrivateKey);
            return ownerId + "-ED25519-" + saved.getVersion();
        } catch (Exception e) {
            throw new RuntimeException("Failed to rotate Ed25519 key", e);
        }
    }

    public long getActiveKeyCount() {
        if (keyVersionRepository == null) return 0;
        return keyVersionRepository.countActiveKeys();
    }

    public Optional<KeyVersion> getActiveKey(String ownerId, String keyType) {
        return keyVersionRepository.findActiveKey(ownerId, keyType);
    }

    public Optional<KeyVersion> getKeyByVersion(String ownerId, String keyType, Integer version) {
        return keyVersionRepository.findByOwnerAndTypeAndVersion(ownerId, keyType, version);
    }

    @Transactional
    public KeyVersion rotateKey(String ownerId, String keyType, String newPublicKey, String newPrivateKeyEncrypted) {
        List<KeyVersion> existingKeys = keyVersionRepository.findByOwnerAndType(ownerId, keyType);

        int nextVersion = existingKeys.isEmpty() ? 1 :
            existingKeys.stream().mapToInt(KeyVersion::getVersion).max().orElse(0) + 1;

        for (KeyVersion existing : existingKeys) {
            existing.setActive(false);
            existing.setValidTo(Instant.now());
            existing.setRotatedAt(Instant.now());
            keyVersionRepository.save(existing);
        }

        KeyVersion newKey = new KeyVersion();
        newKey.setOwnerId(ownerId);
        newKey.setVersion(nextVersion);
        newKey.setKeyType(keyType);
        newKey.setPublicKey(newPublicKey);
        newKey.setPrivateKeyEncrypted(newPrivateKeyEncrypted);
        newKey.setActive(true);
        newKey.setValidFrom(Instant.now());

        KeyVersion saved = keyVersionRepository.save(newKey);
        log.info("[KEY_ROTATION] owner={} type={} newVersion={}", ownerId, keyType, nextVersion);

        // Immediate Cache Invalidation
        if (keyService != null) {
            keyService.clearCache(ownerId);
        }

        return saved;
    }

    public List<KeyVersion> getKeyHistory(String ownerId, String keyType) {
        return keyVersionRepository.findByOwnerAndTypeOrderByVersionDesc(ownerId, keyType);
    }

    public List<KeyVersion> getKeyVersions(String ownerId) {
        return keyVersionRepository.findByOwnerAndTypeOrderByVersionDesc(ownerId, "RSA");
    }

    @Transactional
    public KeyVersion rotateRSAKey(String ownerId, String newPublicKey, String newPrivateKeyEncrypted) {
        return rotateKey(ownerId, "RSA", newPublicKey, newPrivateKeyEncrypted);
    }

    @Transactional
    public KeyVersion rotateEd25519Key(String ownerId, String newPublicKey, String newPrivateKeyEncrypted) {
        return rotateKey(ownerId, "ED25519", newPublicKey, newPrivateKeyEncrypted);
    }

    @Scheduled(cron = "${app.key-rotation.schedule:0 0 * * * ?}")
    public void cleanupExpiredKeys() {
        Instant now = Instant.now();
        List<KeyVersion> expiredKeys = keyVersionRepository.findExpiredKeys(now);

        for (KeyVersion key : expiredKeys) {
            log.info("[KEY_CLEANUP] owner={} type={} version={} expired at {}",
                key.getOwnerId(), key.getKeyType(), key.getVersion(), key.getValidTo());
        }
    }
}