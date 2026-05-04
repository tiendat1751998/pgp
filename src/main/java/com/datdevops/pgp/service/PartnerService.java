package com.datdevops.pgp.service;

import com.datdevops.pgp.dto.internal.PartnerDto;
import com.datdevops.pgp.dto.response.PartnerOnboardResponse;
import com.datdevops.pgp.entity.Partner;
import com.datdevops.pgp.repository.PartnerRepository;
import com.datdevops.pgp.mapper.EntityMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
public class PartnerService {

    @Value("${app.admin-public-key:}")
    private String adminPublicKeyBase64;

    private final PartnerRepository partnerRepository;
    private final SecretEncryptionService secretEncryptionService;
    private final KeyStorageService keyStorageService;
    private final KeyPairGeneratorService keyPairGeneratorService;
    private final RSAKeyPairGeneratorService rsaKeyPairGeneratorService;
    private final EncryptionService encryptionService;
    private final EntityMapper entityMapper;

    private final Cache<String, Partner> partnerCache;

    public PartnerService(
            PartnerRepository partnerRepository,
            SecretEncryptionService secretEncryptionService,
            KeyStorageService keyStorageService,
            KeyPairGeneratorService keyPairGeneratorService,
            RSAKeyPairGeneratorService rsaKeyPairGeneratorService,
            EncryptionService encryptionService,
            EntityMapper entityMapper) {
        this.partnerRepository = partnerRepository;
        this.secretEncryptionService = secretEncryptionService;
        this.keyStorageService = keyStorageService;
        this.keyPairGeneratorService = keyPairGeneratorService;
        this.rsaKeyPairGeneratorService = rsaKeyPairGeneratorService;
        this.encryptionService = encryptionService;
        this.entityMapper = entityMapper;

        this.partnerCache = Caffeine.newBuilder()
                .maximumSize(10000)
                .expireAfterWrite(1, TimeUnit.HOURS)
                .build();
    }

    public PartnerOnboardResponse onboardPartner(String id, String name, String customerRsaPubKey,
            String customerEdPubKey) throws Exception {
        // Validate inputs
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("Partner ID cannot be empty");
        }
        if (partnerRepository.findById(id).isPresent()) {
            throw new IllegalArgumentException("Partner already exists: " + id);
        }

        // Generate keys for THIS partner
        var ourEdKeyPair = keyPairGeneratorService.generateEd25519KeyPair();
        var ourRsaKeyPair = rsaKeyPairGeneratorService.generateRSAKeyPair();

        String ourEdPubKeyBase64 = entityMapper
                .toBase64(keyPairGeneratorService.getEd25519PublicKey(ourEdKeyPair).getEncoded());
        String ourRsaPubKeyBase64 = rsaKeyPairGeneratorService.getBase64PublicKey(ourRsaKeyPair);

        // Generate unique password for THIS partner
        String rawPassword = UUID.randomUUID().toString();

        // Save keystore with partner-specific filename
        String keystoreFileName = id + "-keystore.p12";
        keyStorageService.savePartnerKeyStore(
                id,
                keystoreFileName,
                "system-key",
                entityMapper.toJavaPrivateKey(rsaKeyPairGeneratorService.getPrivateKey(ourRsaKeyPair)),
                new java.security.cert.Certificate[] {},
                rawPassword);

        // Save signature key with partner-specific filename
        String signatureKeyFileName = id + "-signature.key";
        keyStorageService.savePartnerKey(id, signatureKeyFileName,
                keyPairGeneratorService.getEd25519PrivateKey(ourEdKeyPair).getEncoded());

        // Create partner entity
        Partner partner = new Partner();
        partner.setId(id);
        partner.setName(name);
        partner.setCustomerRsaPublicKey(customerRsaPubKey);
        partner.setCustomerEd25519PublicKey(customerEdPubKey);
        partner.setSystemRsaPublicKey(ourRsaPubKeyBase64);
        partner.setSystemEd25519PublicKey(ourEdPubKeyBase64);

        // Encrypt password with master key
        partner.setKeystorePassword(secretEncryptionService.encrypt(rawPassword));

        // Encrypt password for admin if provided
        if (adminPublicKeyBase64 != null && !adminPublicKeyBase64.isBlank()) {
            try {
                // Validate admin key is valid base64
                byte[] adminKeyBytes = Base64.getDecoder().decode(adminPublicKeyBase64);
                if (adminKeyBytes.length > 100) { // Reasonable RSA key size
                    org.bouncycastle.crypto.params.RSAKeyParameters adminKey = entityMapper
                            .toRSAPublicKey(adminKeyBytes);
                    byte[] encryptedForAdmin = encryptionService.encryptSessionKey(rawPassword.getBytes(), adminKey);
                    partner.setAdminEncryptedKeystorePassword(entityMapper.toBase64(encryptedForAdmin));
                }
            } catch (Exception e) {
                // Admin encryption failed - continue without it, log warning
                System.err.println("Warning: Failed to encrypt password for admin: " + e.getMessage());
            }
        }

        Partner savedPartner = partnerRepository.save(partner);
        partnerCache.put(id, savedPartner);

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

    public String getInternalKeystorePassword(String partnerId) throws Exception {
        Partner partner = getPartner(partnerId)
                .orElseThrow(() -> new IllegalArgumentException("Partner not found: " + partnerId));

        if (partner.getKeystorePassword() == null) {
            throw new IllegalStateException("No password stored for partner: " + partnerId);
        }

        return secretEncryptionService.decrypt(partner.getKeystorePassword());
    }

    @CacheEvict(value = "partners", key = "#partnerId")
    public void updateKeystorePassword(String partnerId, String newRawPassword) throws Exception {
        Partner partner = getPartner(partnerId)
                .orElseThrow(() -> new IllegalArgumentException("Partner not found: " + partnerId));

        String keystoreFileName = partnerId + "-keystore.p12";
        keyStorageService.savePartnerKeyStore(
                partnerId,
                keystoreFileName,
                "system-key",
                entityMapper.toJavaPrivateKey(rsaKeyPairGeneratorService.getPrivateKey(
                        rsaKeyPairGeneratorService.generateRSAKeyPair())),
                new java.security.cert.Certificate[] {},
                newRawPassword);

        partner.setKeystorePassword(secretEncryptionService.encrypt(newRawPassword));
        partnerRepository.save(partner);
    }

    public List<Partner> getAllPartners() {
        return Collections.unmodifiableList(partnerRepository.findAll());
    }

    @CacheEvict(value = "partners", key = "#id")
    public void removePartner(String id) {
        partnerRepository.deleteById(id);
        keyStorageService.deletePartnerKeys(id);
    }
}