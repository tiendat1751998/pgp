package com.datdevops.pgp.service;

import com.datdevops.pgp.dto.internal.PartnerDto;
import com.datdevops.pgp.dto.response.PartnerOnboardResponse;
import com.datdevops.pgp.entity.Partner;
import com.datdevops.pgp.repository.PartnerRepository;
import com.datdevops.pgp.repository.KeyVersionRepository;
import com.datdevops.pgp.repository.KeyVersionInfoRepository;
import com.datdevops.pgp.mapper.EntityMapper;
import org.springframework.transaction.annotation.Transactional;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.*;

/**
 * Service for managing partner lifecycle, identity, and cryptographic keys.
 * Hardened to prevent disk/DB inconsistencies and insecure key rotation.
 */
@Service
public class PartnerService {

    private static final Logger log = LoggerFactory.getLogger(PartnerService.class);

    @Value("${app.admin-public-key:}")
    private String adminPublicKeyBase64;

    @Value("${app.security.enable-admin-recovery:false}")
    private boolean enableAdminRecovery;

    private final PartnerRepository partnerRepository;
    private final SecretEncryptionService secretEncryptionService;
    private final KeyStorageService keyStorageService;
    private final KeyPairGeneratorService keyPairGeneratorService;
    private final RSAKeyPairGeneratorService rsaKeyPairGeneratorService;
    private final EncryptionService encryptionService;
    private final EntityMapper entityMapper;
    private final KeyVersionRepository keyVersionRepository;
    private final KeyVersionInfoRepository keyVersionInfoRepository;

    private final Cache<String, Partner> partnerCache;

    public PartnerService(
            PartnerRepository partnerRepository,
            SecretEncryptionService secretEncryptionService,
            KeyStorageService keyStorageService,
            KeyPairGeneratorService keyPairGeneratorService,
            RSAKeyPairGeneratorService rsaKeyPairGeneratorService,
            EncryptionService encryptionService,
            EntityMapper entityMapper,
            KeyVersionRepository keyVersionRepository,
            KeyVersionInfoRepository keyVersionInfoRepository) {
        this.partnerRepository = partnerRepository;
        this.secretEncryptionService = secretEncryptionService;
        this.keyStorageService = keyStorageService;
        this.keyPairGeneratorService = keyPairGeneratorService;
        this.rsaKeyPairGeneratorService = rsaKeyPairGeneratorService;
        this.encryptionService = encryptionService;
        this.entityMapper = entityMapper;
        this.keyVersionRepository = keyVersionRepository;
        this.keyVersionInfoRepository = keyVersionInfoRepository;

        this.partnerCache = Caffeine.newBuilder()
                .maximumSize(10000)
                .expireAfterWrite(1, TimeUnit.HOURS)
                .build();
    }

    /**
     * Onboards a new partner, generates keys, and ensures consistency between DB
     * and Filesystem.
     */
    public PartnerOnboardResponse onboardPartner(String id, String name, String customerRsaPubKey,
            String customerEdPubKey) throws Exception {
        
        // Sanitize name to prevent Stored XSS
        String sanitizedName = name != null ? name.replaceAll("<[^>]*>", "").trim() : "Unknown";

        // 1. Validation
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("Partner ID cannot be empty");
        }
        if (partnerRepository.findById(id).isPresent()) {
            throw new IllegalArgumentException("Partner already exists: " + id);
        }

        // Validate RSA key length (minimum 2048-bit)
        if (customerRsaPubKey != null && !customerRsaPubKey.isBlank()) {
            try {
                byte[] rsaKeyBytes = Base64.getDecoder().decode(customerRsaPubKey);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(rsaKeyBytes);
                RSAPublicKey rsaKey = (RSAPublicKey) kf.generatePublic(keySpec);
                
                int keyLengthBits = rsaKey.getModulus().bitLength();
                if (keyLengthBits < 2048) {
                    throw new SecurityException("RSA key must be at least 2048-bit. Provided: " + keyLengthBits + "-bit");
                }
                log.info("[SECURITY] RSA key validated: {} bits", keyLengthBits);
            } catch (InvalidKeySpecException e) {
                throw new IllegalArgumentException("Invalid RSA key format: must be X.509 encoded public key");
            } catch (Exception e) {
                log.error("[SECURITY] RSA validation error: {}", e.getMessage());
                throw new SecurityException("Failed to validate RSA key: " + e.getMessage());
            }
        }

        // 2. Key Generation
        var ourEdKeyPair = keyPairGeneratorService.generateEd25519KeyPair();
        var ourRsaKeyPair = rsaKeyPairGeneratorService.generateRSAKeyPair();

        String ourEdPubKeyBase64 = entityMapper
                .toBase64(keyPairGeneratorService.getEd25519PublicKey(ourEdKeyPair).getEncoded());
        String ourRsaPubKeyBase64 = rsaKeyPairGeneratorService.getBase64PublicKey(ourRsaKeyPair);

        String rawPassword = UUID.randomUUID().toString();

        // 3. Create Entity (Not saved yet)
        Partner partner = new Partner();
        partner.setId(id);
        partner.setName(sanitizedName);
        partner.setCustomerRsaPublicKey(customerRsaPubKey);
        partner.setCustomerEd25519PublicKey(customerEdPubKey);
        partner.setSystemRsaPublicKey(ourRsaPubKeyBase64);
        partner.setSystemEd25519PublicKey(ourEdPubKeyBase64);
        partner.setKeystorePassword(secretEncryptionService.encrypt(rawPassword));

        // 4. Admin Key Encryption (Controlled by feature flag)
        if (enableAdminRecovery && adminPublicKeyBase64 != null && !adminPublicKeyBase64.isBlank()) {
            try {
                byte[] adminKeyBytes = Base64.getDecoder().decode(adminPublicKeyBase64);
                if (adminKeyBytes.length > 100) {
                    RSAKeyParameters adminKey = entityMapper.toRSAPublicKey(adminKeyBytes);
                    byte[] encryptedForAdmin = encryptionService.encryptSessionKey(rawPassword.getBytes(), adminKey);
                    partner.setAdminEncryptedKeystorePassword(entityMapper.toBase64(encryptedForAdmin));
                    log.info("[SECURITY] Admin recovery enabled for partner: {}", id);
                }
            } catch (Exception e) {
                log.warn("Failed to encrypt password for admin: {}", e.getMessage());
            }
        }

        // 5. Save to DB FIRST to ensure uniqueness and audit trail
        Partner savedPartner = partnerRepository.save(partner);
        partnerCache.put(id, savedPartner);

        // 6. Save to Filesystem
        char[] passwordChars = rawPassword.toCharArray();
        try {
            String keystoreFileName = id + "-keystore.p12";
            keyStorageService.savePartnerKeyStore(
                    id,
                    keystoreFileName,
                    "system-key",
                    entityMapper.toJavaPrivateKey(rsaKeyPairGeneratorService.getPrivateKey(ourRsaKeyPair)),
                    new Certificate[] {},
                    passwordChars);

            String signatureKeyFileName = id + "-signature.key";
            keyStorageService.savePartnerKey(id, signatureKeyFileName,
                    keyPairGeneratorService.getEd25519PrivateKey(ourEdKeyPair).getEncoded());

            log.info("[PARTNER] Onboarding successful: {}", id);
        } catch (Exception e) {
            log.error("[PARTNER] Filesystem error during onboarding for {}. Rolling back DB.", id, e);
            partnerRepository.deleteById(id);
            partnerCache.invalidate(id);
            throw new IllegalStateException("Failed to persist partner keys: " + e.getMessage());
        } finally {
            Arrays.fill(passwordChars, '\0');
        }

        return new PartnerOnboardResponse(
                savedPartner,
                rawPassword,
                "Store this password securely. Required to decrypt partner messages.");
    }

    public Optional<Partner> getPartner(String id) {
        Partner cached = partnerCache.getIfPresent(id);
        if (cached != null) {
            return Optional.of(cached);
        }
        Optional<Partner> partnerOpt = partnerRepository.findById(id);
        partnerOpt.ifPresent(p -> partnerCache.put(id, p));
        return partnerOpt;
    }

    public Optional<PartnerDto> getPartnerDto(String id) {
        return getPartner(id).map(entityMapper::toPartnerDto);
    }

    public long getCacheSize() {
        return partnerCache.estimatedSize();
    }

    public String getInternalKeystorePassword(String partnerId) {
        byte[] bytes = getInternalKeystorePasswordBytes(partnerId);
        if (bytes == null) return null;
        try {
            return new String(bytes, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    public byte[] getInternalKeystorePasswordBytes(String partnerId) {
        Partner partner = partnerRepository.findById(partnerId)
                .orElseThrow(() -> new IllegalArgumentException("Partner not found: " + partnerId));

        if (partner.getKeystorePassword() == null) {
            return null;
        }

        try {
            return secretEncryptionService.decryptToBytes(partner.getKeystorePassword());
        } catch (Exception e) {
            log.error("Failed to decrypt keystore password for partner: {}", partnerId, e);
            throw new RuntimeException("Could not retrieve keystore password");
        }
    }

    /**
     * Updates the keystore password while PRESERVING the existing private key.
     * Hardened against key destruction.
     */
    public void updateKeystorePassword(String partnerId, String newRawPassword) throws Exception {
        Partner partner = getPartner(partnerId)
                .orElseThrow(() -> new IllegalArgumentException("Partner not found: " + partnerId));

        String keystoreFileName = partnerId + "-keystore.p12";
        byte[] currentPasswordBytes = getInternalKeystorePasswordBytes(partnerId);
        if (currentPasswordBytes == null) {
            throw new SecurityException("Cannot update password: current password not found");
        }
        
        char[] currentPasswordChars = StandardCharsets.UTF_8.decode(java.nio.ByteBuffer.wrap(currentPasswordBytes)).array();
        char[] newPasswordChars = newRawPassword.toCharArray();

        try {
            // 1. Load existing private key
            PrivateKey existingPrivateKey = keyStorageService.getPrivateKeyFromStore(
                    partnerId, keystoreFileName, "system-key", currentPasswordChars);

            // 2. Re-save with new password (same key material)
            keyStorageService.savePartnerKeyStore(
                    partnerId,
                    keystoreFileName,
                    "system-key",
                    existingPrivateKey,
                    new Certificate[] {},
                    newPasswordChars);

            // 3. Update DB and Cache
            partner.setKeystorePassword(secretEncryptionService.encrypt(newRawPassword));
            Partner saved = partnerRepository.save(partner);
            partnerCache.put(partnerId, saved);

            log.info("[PARTNER] Password updated for: {} (keys preserved)", partnerId);
        } finally {
            Arrays.fill(currentPasswordBytes, (byte) 0);
            Arrays.fill(currentPasswordChars, '\0');
            Arrays.fill(newPasswordChars, '\0');
        }
    }

    public List<Partner> getAllPartners() {
        return Collections.unmodifiableList(partnerRepository.findAll());
    }

    public PartnerDto toPartnerDto(Partner partner) {
        return entityMapper.toPartnerDto(partner);
    }

    @Transactional
    public void removePartner(String id) {
        log.info("[SECURITY] Initiating full removal for partner: {}", id);
        
        // 1. Invalidate Cache
        partnerCache.invalidate(id);
        
        // 2. Cleanup all associated key metadata and versions to prevent Data Residuals
        if (keyVersionRepository != null) {
            log.debug("[CLEANUP] Deleting key versions for: {}", id);
            keyVersionRepository.deleteByOwnerId(id);
        }
        
        if (keyVersionInfoRepository != null) {
            log.debug("[CLEANUP] Deleting key info for: {}", id);
            keyVersionInfoRepository.deleteByEntityId(id);
        }
        
        keyStorageService.deletePartnerKeys(id);
        
        // 3. Delete the main partner entity
        partnerRepository.deleteById(id);
        
        log.info("[PARTNER] Full cleanup completed for: {}", id);
    }
}