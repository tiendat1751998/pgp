package com.datdevops.pgp.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.datdevops.pgp.repository.PartnerRepository;
import com.datdevops.pgp.entity.Partner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.regex.Pattern;

/**
 * Dedicated service for keystore and key file operations.
 * Extracts filesystem operations from PartnerService (Single Responsibility
 * Principle).
 */
@Service
public class KeyStoreStorageService {

    private static final Logger log = LoggerFactory.getLogger(KeyStoreStorageService.class);

    private static final Pattern SAFE_PARTNER_ID = Pattern.compile("^[a-zA-Z0-9_-]+$");

    @Value("${app.key-store-path:./vault/}")
    private String vaultPath;

    private final KeyStorageService keyStorageService;
    private final PartnerRepository partnerRepository;
    private final SecretEncryptionService secretEncryptionService;

    public KeyStoreStorageService(
            KeyStorageService keyStorageService,
            PartnerRepository partnerRepository,
            SecretEncryptionService secretEncryptionService) {
        this.keyStorageService = keyStorageService;
        this.partnerRepository = partnerRepository;
        this.secretEncryptionService = secretEncryptionService;
    }

    /**
     * Save keystore for a partner.
     */
    public void saveKeystore(String partnerId, PrivateKey privateKey, Certificate[] chain, char[] password)
            throws Exception {
        validatePartnerId(partnerId);

        String keystoreFileName = partnerId + "-keystore.p12";
        try {
            keyStorageService.savePartnerKeyStore(
                    partnerId,
                    keystoreFileName,
                    "system-key",
                    privateKey,
                    chain,
                    password);
        } finally {
            // Securely wipe the password array
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }

        log.info("[KEYSTORE] Saved for partner: {}", partnerId);
    }

    /**
     * Save signature key for a partner.
     */
    public void saveSignatureKey(String partnerId, byte[] privateKeyBytes) throws IOException {
        validatePartnerId(partnerId);

        String signatureKeyFileName = partnerId + "-signature.key";
        keyStorageService.savePartnerKey(partnerId, signatureKeyFileName, privateKeyBytes);

        log.info("[SIGNATURE_KEY] Saved for partner: {}", partnerId);
    }

    /**
     * Load keystore password bytes for a partner.
     * Use bytes to allow secure wiping from memory.
     */
    public byte[] loadKeystorePasswordBytes(String partnerId) throws Exception {
        validatePartnerId(partnerId);
        Partner partner = partnerRepository.findById(partnerId)
                .orElseThrow(() -> new IllegalArgumentException("Partner not found: " + partnerId));
        return secretEncryptionService.decryptToBytes(partner.getKeystorePassword());
    }

    /**
     * Delete all keys for a partner.
     */
    public void deleteAllKeys(String partnerId) {
        validatePartnerId(partnerId);
        keyStorageService.deletePartnerKeys(partnerId);
        log.info("[KEYS] Deleted all keys for partner: {}", partnerId);
    }

    /**
     * Validate partner ID to prevent path traversal attacks.
     */
    public void validatePartnerId(String partnerId) {
        if (partnerId == null || !SAFE_PARTNER_ID.matcher(partnerId).matches()) {
            log.error("[SECURITY] Path traversal attempt or invalid partnerId: {}", partnerId);
            throw new IllegalArgumentException("Invalid partnerId format");
        }
    }

    /**
     * Check if partner keys exist.
     */
    public boolean keysExist(String partnerId) {
        try {
            validatePartnerId(partnerId);
            Path keystorePath = Paths.get(vaultPath, partnerId, "keys", partnerId + "-keystore.p12");
            return Files.exists(keystorePath);
        } catch (Exception e) {
            return false;
        }
    }
}