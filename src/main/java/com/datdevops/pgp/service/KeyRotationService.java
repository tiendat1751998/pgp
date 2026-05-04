package com.datdevops.pgp.service;

import com.datdevops.pgp.entity.KeyVersionInfo;
import com.datdevops.pgp.repository.KeyVersionInfoRepository;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Service
public class KeyRotationService {

    private static final Logger log = LoggerFactory.getLogger(KeyRotationService.class);

    private final KeyPairGeneratorService keyPairGeneratorService;
    private final RSAKeyPairGeneratorService rsaKeyPairGeneratorService;
    private final KeyVersionInfoRepository keyVersionInfoRepository;
    private final ConcurrentMap<String, KeyVersionInfo> localCache = new ConcurrentHashMap<>();

    public KeyRotationService(
            KeyPairGeneratorService keyPairGeneratorService,
            RSAKeyPairGeneratorService rsaKeyPairGeneratorService,
            KeyVersionInfoRepository keyVersionInfoRepository) {
        this.keyPairGeneratorService = keyPairGeneratorService;
        this.rsaKeyPairGeneratorService = rsaKeyPairGeneratorService;
        this.keyVersionInfoRepository = keyVersionInfoRepository;
    }

    public KeyRotationService() {
        this.keyPairGeneratorService = new KeyPairGeneratorService();
        this.rsaKeyPairGeneratorService = new RSAKeyPairGeneratorService();
        this.keyVersionInfoRepository = null;
    }

    @Transactional
    public String rotateRSAKey(String entityId) throws Exception {
        if (keyVersionInfoRepository == null) {
            log.warn("Running without repository - key version not persisted");
            return rotateRSAKeyFallback(entityId);
        }

        var keyPair = rsaKeyPairGeneratorService.generateRSAKeyPair();
        String version = generateVersion();
        String keyId = entityId + "-RSA-" + version;

        keyVersionInfoRepository.deactivatePreviousVersions(entityId, "RSA");

        KeyVersionInfo kv = new KeyVersionInfo();
        kv.setKeyId(keyId);
        kv.setEntityId(entityId);
        kv.setKeyType("RSA");
        kv.setVersion(version);
        kv.setRsaPublicKey(rsaKeyPairGeneratorService.getBase64PublicKey(keyPair));
        kv.setCreatedAt(Instant.now());
        kv.setActive(true);

        keyVersionInfoRepository.save(kv);
        log.info("Rotated RSA key for entity {}: {}", entityId, keyId);

        return keyId;
    }

    @Transactional
    public String rotateEd25519Key(String entityId) throws Exception {
        if (keyVersionInfoRepository == null) {
            log.warn("Running without repository - key version not persisted");
            return rotateEd25519KeyFallback(entityId);
        }

        var keyPair = keyPairGeneratorService.generateEd25519KeyPair();
        String version = generateVersion();
        String keyId = entityId + "-ED25519-" + version;

        keyVersionInfoRepository.deactivatePreviousVersions(entityId, "ED25519");

        byte[] publicKeyBytes = keyPairGeneratorService.getEd25519PublicKey(keyPair).getEncoded();
        String publicKeyBase64 = java.util.Base64.getEncoder().encodeToString(publicKeyBytes);

        KeyVersionInfo kv = new KeyVersionInfo();
        kv.setKeyId(keyId);
        kv.setEntityId(entityId);
        kv.setKeyType("ED25519");
        kv.setVersion(version);
        kv.setEd25519PublicKey(publicKeyBase64);
        kv.setCreatedAt(Instant.now());
        kv.setActive(true);

        keyVersionInfoRepository.save(kv);
        log.info("Rotated Ed25519 key for entity {}: {}", entityId, keyId);

        return keyId;
    }

    public KeyVersionInfo getActiveKey(String entityId, String keyType) {
        if (keyVersionInfoRepository == null) {
            return localCache.values().stream()
                    .filter(kv -> kv.isActive() && kv.getEntityId().equals(entityId) && kv.getKeyType().equals(keyType))
                    .findFirst()
                    .orElse(null);
        }
        return keyVersionInfoRepository.findByEntityIdAndKeyTypeAndActiveTrue(entityId, keyType)
                .orElse(null);
    }

    public KeyVersionInfo getKeyVersionById(String keyId) {
        if (keyVersionInfoRepository == null) {
            return null;
        }
        Optional<KeyVersionInfo> kv = keyVersionInfoRepository.findById(keyId);
        if (kv.isEmpty()) {
            return null;
        }
        if (!kv.get().isActive()) {
            throw new SecurityException("Key version is deactivated: " + keyId);
        }
        return kv.get();
    }

    public List<KeyVersionInfo> getKeyVersions(String entityId) {
        if (keyVersionInfoRepository == null) {
            return localCache.values().stream()
                    .filter(kv -> kv.getEntityId().equals(entityId))
                    .collect(java.util.stream.Collectors.toList());
        }
        return keyVersionInfoRepository.findByEntityIdOrderByCreatedAtDesc(entityId);
    }

    @Transactional
    public boolean deactivateKey(String keyId) {
        if (keyVersionInfoRepository == null) {
            return false;
        }
        Optional<KeyVersionInfo> kvOpt = keyVersionInfoRepository.findById(keyId);
        if (kvOpt.isPresent()) {
            KeyVersionInfo kv = kvOpt.get();
            kv.setActive(false);
            keyVersionInfoRepository.save(kv);
            return true;
        }
        return false;
    }

    public int getActiveKeyCount() {
        if (keyVersionInfoRepository == null) {
            return (int) localCache.values().stream().filter(KeyVersionInfo::isActive).count();
        }
        return (int) keyVersionInfoRepository.countActiveKeys();
    }

    private String generateVersion() {
        return String.valueOf(System.currentTimeMillis());
    }

    private KeyVersionInfo getActiveKeyFallback(String entityId, String keyType) {
        log.warn("Running in fallback mode - key versions not persisted to database");
        return null;
    }

    private String rotateRSAKeyFallback(String entityId) throws Exception {
        var keyPair = rsaKeyPairGeneratorService.generateRSAKeyPair();
        String version = generateVersion();
        String keyId = entityId + "-RSA-" + version;

        KeyVersionInfo kv = new KeyVersionInfo();
        kv.setKeyId(keyId);
        kv.setEntityId(entityId);
        kv.setKeyType("RSA");
        kv.setVersion(version);
        kv.setRsaPublicKey(rsaKeyPairGeneratorService.getBase64PublicKey(keyPair));
        kv.setCreatedAt(Instant.now());
        kv.setActive(true);

        localCache.put(keyId, kv);
        log.warn("Fallback mode: Generated and cached RSA key {}", keyId);
        return keyId;
    }

    private String rotateEd25519KeyFallback(String entityId) throws Exception {
        var keyPair = keyPairGeneratorService.generateEd25519KeyPair();
        String version = generateVersion();
        String keyId = entityId + "-ED25519-" + version;

        byte[] publicKeyBytes = keyPairGeneratorService.getEd25519PublicKey(keyPair).getEncoded();
        String publicKeyBase64 = java.util.Base64.getEncoder().encodeToString(publicKeyBytes);

        KeyVersionInfo kv = new KeyVersionInfo();
        kv.setKeyId(keyId);
        kv.setEntityId(entityId);
        kv.setKeyType("ED25519");
        kv.setVersion(version);
        kv.setEd25519PublicKey(publicKeyBase64);
        kv.setCreatedAt(Instant.now());
        kv.setActive(true);

        localCache.put(keyId, kv);
        log.warn("Fallback mode: Generated and cached Ed25519 key {}", keyId);
        return keyId;
    }

    public void loadFromDatabase() {
        if (keyVersionInfoRepository != null) {
            List<KeyVersionInfo> allActive = keyVersionInfoRepository.findAllActive();
            log.info("Loaded {} active key versions from database", allActive.size());
        }
    }
}