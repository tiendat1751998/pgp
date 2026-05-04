package com.datdevops.pgp.service;

import com.datdevops.pgp.entity.Partner;
import com.datdevops.pgp.mapper.EntityMapper;
import com.datdevops.pgp.security.SenderContext;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
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

    private final Cache<String, RSAKeyParameters> rsaKeyCache;
    private final Cache<String, Ed25519PrivateKeyParameters> edPrivateKeyCache;
    private final Cache<String, Ed25519PublicKeyParameters> edPublicKeyCache;

    public KeyService(PartnerService partnerService, 
                      KeyStorageService keyStorageService, 
                      EntityMapper entityMapper) {
        this.partnerService = partnerService;
        this.keyStorageService = keyStorageService;
        this.entityMapper = entityMapper;

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
                Partner partner = partnerService.getPartner(actualId)
                        .orElseThrow(() -> new IllegalArgumentException("Recipient not found: " + actualId));
                return entityMapper.toRSAPublicKey(partner.getCustomerRsaPublicKey());
            } catch (Exception e) {
                log.error("Failed to load public key for recipient: {}", id, e);
                throw new RuntimeException("Could not load recipient public key");
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
                String rawPassword = partnerService.getInternalKeystorePassword(actualId);
                PrivateKey privateKey = keyStorageService.getPrivateKeyFromStore(
                        actualId, actualId + "-keystore.p12", "system-key", rawPassword);
                return entityMapper.toRSAPrivateKey(privateKey);
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
}
