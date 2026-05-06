package com.datdevops.pgp.service;

import com.datdevops.pgp.entity.Partner;
import com.datdevops.pgp.mapper.EntityMapper;
import com.datdevops.pgp.repository.KeyVersionRepository;
import com.datdevops.pgp.security.SenderContext;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

/**
 * High-performance Key Service that centralizes key access and caching.
 * Enforces strict key isolation and ownership.
 */
@Service
public class KeyService {
    private static final Logger log = LoggerFactory.getLogger(KeyService.class);

    private final PartnerService partnerService;
    private final KeyStorageService keyStorageService;
    private final EntityMapper entityMapper;
    private final KeyVersionRepository keyVersionRepository;
    private final SecretEncryptionService secretEncryptionService;

    private final Cache<String, RSAKeyParameters> rsaKeyCache;
    private final Cache<String, Ed25519PrivateKeyParameters> edPrivateKeyCache;
    private final Cache<String, Ed25519PublicKeyParameters> edPublicKeyCache;

    public KeyService(PartnerService partnerService,
            KeyStorageService keyStorageService,
            EntityMapper entityMapper,
            KeyVersionRepository keyVersionRepository,
            SecretEncryptionService secretEncryptionService) {
        this.partnerService = partnerService;
        this.keyStorageService = keyStorageService;
        this.entityMapper = entityMapper;
        this.keyVersionRepository = keyVersionRepository;
        this.secretEncryptionService = secretEncryptionService;

        this.rsaKeyCache = Caffeine.newBuilder()
                .maximumSize(1000)
                .expireAfterAccess(30, TimeUnit.MINUTES)
                .build();
        this.edPrivateKeyCache = Caffeine.newBuilder()
                .maximumSize(1000)
                .expireAfterAccess(30, TimeUnit.MINUTES)
                .build();
        this.edPublicKeyCache = Caffeine.newBuilder()
                .maximumSize(1000)
                .expireAfterAccess(60, TimeUnit.MINUTES)
                .build();
    }

    /**
     * Retrieves the sender's Ed25519 private key for signing.
     * Enforces that the requested key belongs to the authenticated sender.
     */
    public Ed25519PrivateKeyParameters getSenderSigningKey(String senderId) {
        validateOwnership(senderId);

        return edPrivateKeyCache.get(senderId, id -> {
            try {
                // Priority 1: Check Database for rotated keys
                var rotatedKey = keyVersionRepository.findActiveKey(id, "ED25519");
                if (rotatedKey.isPresent()) {
                    String encryptedPriv = rotatedKey.get().getPrivateKeyEncrypted();
                    byte[] keyBytes = secretEncryptionService.decryptToBytes(encryptedPriv);
                    try {
                        return new Ed25519PrivateKeyParameters(keyBytes, 0);
                    } finally {
                        Arrays.fill(keyBytes, (byte) 0);
                    }
                }

                // Priority 2: Fallback to Legacy Filesystem
                byte[] keyBytes = keyStorageService.loadPartnerKey(id, id + "-signature.key");
                return new Ed25519PrivateKeyParameters(keyBytes, 0);
            } catch (Exception e) {
                log.error("Failed to load signing key for sender: {}", id, e);
                throw new SecurityException("Could not load signing key");
            }
        });
    }

    /**
     * Retrieves the recipient's RSA public key for session key encryption.
     */
    public RSAKeyParameters getRecipientPublicKey(String recipientId) {
        return rsaKeyCache.get(recipientId + "-PUB", id -> {
            try {
                String actualId = id.substring(0, id.length() - 4);

                // Priority 1: Check Database for rotated keys
                var rotatedKey = keyVersionRepository.findActiveKey(actualId, "RSA");
                if (rotatedKey.isPresent()) {
                    return entityMapper.toRSAPublicKey(rotatedKey.get().getPublicKey());
                }

                // Priority 2: Fallback to Partner Entity
                Partner partner = partnerService.getPartner(actualId)
                        .orElseThrow(() -> new IllegalArgumentException("Recipient not found: " + actualId));
                return entityMapper.toRSAPublicKey(partner.getCustomerRsaPublicKey());
            } catch (Exception e) {
                log.error("Failed to load public key for recipient: {}", id, e);
                throw new RuntimeException("Could not load recipient public key: " + e.getMessage(), e);
            }
        });
    }

    /**
     * Retrieves our (the recipient's) RSA private key for session key decryption.
     * Enforces that the requested key belongs to the authenticated recipient.
     */
    public RSAKeyParameters getOurDecryptionKey(String partnerId) {
        validateOwnership(partnerId);

        return rsaKeyCache.get(partnerId + "-PRIV", id -> {
            try {
                String actualId = id.substring(0, id.length() - 5);

                // Priority 1: Check Database for rotated keys
                var rotatedKey = keyVersionRepository.findActiveKey(actualId, "RSA");
                if (rotatedKey.isPresent()) {
                    String encryptedPriv = rotatedKey.get().getPrivateKeyEncrypted();
                    byte[] decryptedPriv = secretEncryptionService.decryptToBytes(encryptedPriv);
                    try {
                        return entityMapper.toRSAPrivateKey(decryptedPriv);
                    } finally {
                        Arrays.fill(decryptedPriv, (byte) 0);
                    }
                }

                // Priority 2: Fallback to Keystore
                byte[] rawPassword = partnerService.getInternalKeystorePasswordBytes(actualId);
                if (rawPassword == null) {
                    throw new SecurityException("No keystore password found for partner: " + actualId);
                }
                
                // Fix Memory Security: Convert bytes to chars without an intermediate String object if possible
                // Using StandardCharsets to ensure consistent encoding
                char[] passwordChars = StandardCharsets.UTF_8.decode(java.nio.ByteBuffer.wrap(rawPassword)).array();
                
                try {
                    PrivateKey privateKey = keyStorageService.getPrivateKeyFromStore(
                            actualId, actualId + "-keystore.p12", "system-key", passwordChars);
                    return entityMapper.toRSAPrivateKey(privateKey);
                } finally {
                    Arrays.fill(rawPassword, (byte) 0);
                    Arrays.fill(passwordChars, '\0');
                }
            } catch (Exception e) {
                log.error("Failed to load decryption key for partner: {}", id, e);
                throw new SecurityException("Could not load decryption key");
            }
        });
    }

    /**
     * Retrieves the sender's Ed25519 public key for signature verification.
     */
    public Ed25519PublicKeyParameters getSenderVerificationKey(String senderId) {
        return edPublicKeyCache.get(senderId, id -> {
            try {
                // Priority 1: Check Database for rotated keys
                var rotatedKey = keyVersionRepository.findActiveKey(id, "ED25519");
                if (rotatedKey.isPresent()) {
                    byte[] keyBytes = Base64.getDecoder().decode(rotatedKey.get().getPublicKey());
                    return new Ed25519PublicKeyParameters(keyBytes, 0);
                }

                // Priority 2: Fallback to Partner Entity
                Partner partner = partnerService.getPartner(id)
                        .orElseThrow(() -> new IllegalArgumentException("Sender not found: " + id));
                byte[] keyBytes = entityMapper.fromBase64(partner.getCustomerEd25519PublicKey());
                return new Ed25519PublicKeyParameters(keyBytes, 0);
            } catch (Exception e) {
                log.error("Failed to load verification key for sender: {}", id, e);
                throw new RuntimeException("Could not load sender verification key");
            }
        });
    }

    /**
     * Alias for getSenderVerificationKey - retrieves Ed25519 public key for streaming signature verification.
     */
    public Ed25519PublicKeyParameters getSenderEd25519Key(String senderId) {
        return getSenderVerificationKey(senderId);
    }

    /**
     * Get Ed25519 public key by sender ID and version for key rotation support.
     * Enforces a 60-minute grace period for rotated keys.
     */
    public Ed25519PublicKeyParameters getSenderEd25519Key(String senderId, int keyVersion) {
        String cacheKey = senderId + ":V" + keyVersion;
        
        return edPublicKeyCache.get(cacheKey, k -> {
            try {
                var repo = keyVersionRepository;
                if (repo == null) return getSenderVerificationKey(senderId);

                var kvOpt = repo.findByOwnerAndTypeAndVersion(senderId, "ED25519", keyVersion);
                if (kvOpt.isPresent()) {
                    var kv = kvOpt.get();
                    
                    // Enforce Grace Period: Allow if active OR rotated within the last 60 minutes
                    boolean isWithinGracePeriod = !kv.isActive() && kv.getRotatedAt() != null &&
                            kv.getRotatedAt().plus(60, ChronoUnit.MINUTES).isAfter(Instant.now());
                        
                        if (kv.isActive() || isWithinGracePeriod) {
                            if (isWithinGracePeriod) {
                                log.info("[SECURITY] Using rotated key version {} within 60min grace period for: {}", 
                                    kv.getVersion(), senderId);
                            }
                            byte[] keyBytes = Base64.getDecoder().decode(kv.getPublicKey());
                            return new Ed25519PublicKeyParameters(keyBytes, 0);
                    } else {
                        log.warn("[SECURITY] Attempt to use expired key version: {} v{} (Rotated at: {})", 
                                senderId, keyVersion, kv.getRotatedAt());
                        throw new SecurityException("Key version has expired");
                    }
                }
                
                // Fallback to current if version is 1 or not found (legacy support)
                return getSenderVerificationKey(senderId);
            } catch (Exception e) {
                log.error("Failed to load versioned key for sender: {} v{}", senderId, keyVersion, e);
                throw new SecurityException("Could not load sender verification key");
            }
        });
    }

    private void validateOwnership(String id) {
        String authenticatedId = SenderContext.getSenderId();
        if (authenticatedId == null || !authenticatedId.equals(id)) {
            log.warn("Access denied: Authenticated identity {} tried to access key for {}", authenticatedId, id);
            throw new SecurityException("Access denied: You do not own this key");
        }
    }

    public void clearCache(String partnerId) {
        rsaKeyCache.invalidate(partnerId + "-PUB");
        rsaKeyCache.invalidate(partnerId + "-PRIV");
        edPrivateKeyCache.invalidate(partnerId);
        edPublicKeyCache.invalidate(partnerId);
    }

    public KeyVersionRepository getKeyVersionRepository() {
        return keyVersionRepository;
    }
}
