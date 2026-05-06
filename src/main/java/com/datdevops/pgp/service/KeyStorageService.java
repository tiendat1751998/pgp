package com.datdevops.pgp.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.resilience4j.retry.annotation.Retry;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.bulkhead.annotation.Bulkhead;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import jakarta.annotation.PostConstruct;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * Hardened service for secure cryptographic key storage on the filesystem.
 * Implements atomic writes, secure memory handling, and strict permission enforcement.
 */
@Service
public class KeyStorageService {

    private static final Logger log = LoggerFactory.getLogger(KeyStorageService.class);
    private static final Pattern SAFE_PARTNER_ID = Pattern.compile("^[a-zA-Z0-9_-]+$");

    @Value("${app.key-store-path:./vault/}")
    private String vaultPath;

    @Value("${app.keystore.password:}")
    private char[] keystorePassword;

    private final Cache<String, PrivateKey> privateKeyCache;
    private final DistributedLockService lockService;

    public KeyStorageService(DistributedLockService lockService) {
        this.lockService = lockService;
        this.privateKeyCache = Caffeine.newBuilder()
                .maximumSize(1000)
                .expireAfterAccess(30, TimeUnit.MINUTES)
                .build();
    }

    @PostConstruct
    public void init() throws IOException {
        Path vault = Paths.get(vaultPath);
        if (!Files.exists(vault)) {
            Files.createDirectories(vault);
        }
        secureFile(vault);
        log.info("KeyStorageService initialized at: {}", vault.toAbsolutePath());
    }

    private void validatePartnerId(String partnerId) {
        if (partnerId == null || !SAFE_PARTNER_ID.matcher(partnerId).matches()) {
            log.error("[SECURITY] Invalid partnerId pattern detected: {}", partnerId);
            throw new IllegalArgumentException("Invalid partnerId format");
        }
    }

    private Path getPartnerPath(String partnerId) throws IOException {
        validatePartnerId(partnerId);
        Path path = Paths.get(vaultPath, partnerId, "keys");
        if (!Files.exists(path)) {
            Files.createDirectories(path);
        }
        return path;
    }

    // --- Atomic File Operations ---

    public void savePartnerKey(String partnerId, String fileName, byte[] keyData) throws IOException {
        validatePartnerId(partnerId);
        Path partnerDir = getPartnerPath(partnerId);
        Path filePath = partnerDir.resolve(fileName);
        Path tempPath = partnerDir.resolve(fileName + ".tmp");

        try {
            // Fix Security #220: Use restrictive permissions during creation
            Files.write(tempPath, keyData);
            secureFile(tempPath);
            
            // Fix Logic #218: Atomic move to prevent file corruption
            Files.move(tempPath, filePath, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(tempPath);
        }
    }

    public byte[] loadPartnerKey(String partnerId, String fileName) throws IOException {
        Path filePath = getPartnerPath(partnerId).resolve(fileName);
        if (!Files.exists(filePath)) {
            throw new IOException("Key file not found for partner " + partnerId + ": " + fileName);
        }
        return Files.readAllBytes(filePath);
    }

    // --- KeyStore Operations ---

    @Retry(name = "keyStorage")
    @CircuitBreaker(name = "keyStorage")
    public KeyStore loadPartnerKeyStore(String partnerId, String fileName) throws Exception {
        if (fileName == null || fileName.isEmpty()) {
            fileName = partnerId + "-keystore.p12";
        }
        Path filePath = getPartnerPath(partnerId).resolve(fileName);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        
        char[] password = getKeystorePassword();
        try (FileInputStream fis = new FileInputStream(filePath.toFile())) {
            keyStore.load(fis, password);
        } finally {
            clearPassword(password);
        }
        return keyStore;
    }

    private synchronized char[] getKeystorePassword() {
        return (keystorePassword == null) ? new char[0] : keystorePassword.clone();
    }

    private void clearPassword(char[] password) {
        if (password != null) {
            Arrays.fill(password, '\0');
        }
    }

    private void secureFile(Path filePath) {
        try {
            Set<PosixFilePermission> perms = PosixFilePermissions.fromString("r--------");
            Files.setPosixFilePermissions(filePath, perms);
        } catch (UnsupportedOperationException e) {
            // Ignore on non-POSIX systems (Windows)
        } catch (IOException e) {
            log.warn("Could not set restrictive permissions on: {}", filePath);
        }
    }

    @Retry(name = "keyStorage")
    @Bulkhead(name = "keyAccess")
    public PrivateKey getPrivateKeyFromStore(String partnerId, String fileName, String alias, char[] password) throws Exception {
        validatePartnerId(partnerId);
        
        String cacheKey = partnerId + ":" + fileName + ":" + alias;
        PrivateKey cachedKey = privateKeyCache.getIfPresent(cacheKey);
        if (cachedKey != null) {
            return cachedKey;
        }
        
        KeyStore keyStore = loadPartnerKeyStore(partnerId, fileName);
        try {
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password);
            if (privateKey != null) {
                privateKeyCache.put(cacheKey, privateKey);
            }
            return privateKey;
        } finally {
            // Caller is responsible for clearing the input 'password' array
        }
    }

    @Retry(name = "keyStorage")
    public void savePartnerKeyStore(String partnerId, String fileName, String alias, PrivateKey privateKey, Certificate[] chain, char[] password) throws Exception {
        if (lockService != null) {
            String lockResource = partnerId + ":" + fileName;
            lockService.executeWithLock(lockResource, () -> {
                try {
                    doSavePartnerKeyStore(partnerId, fileName, alias, privateKey, chain, password);
                } catch (Exception e) {
                    throw new RuntimeException("Failed to save keystore under lock", e);
                }
                return null;
            });
        } else {
            doSavePartnerKeyStore(partnerId, fileName, alias, privateKey, chain, password);
        }
    }

    private void doSavePartnerKeyStore(String partnerId, String fileName, String alias, PrivateKey privateKey, Certificate[] chain, char[] password) throws Exception {
        Path partnerDir = getPartnerPath(partnerId);
        Path filePath = partnerDir.resolve(fileName);
        Path tempPath = partnerDir.resolve(fileName + ".tmp");
        
        char[] ksPassword = getKeystorePassword();
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            if (Files.exists(filePath)) {
                try (FileInputStream fis = new FileInputStream(filePath.toFile())) {
                    keyStore.load(fis, ksPassword);
                }
            } else {
                keyStore.load(null, ksPassword);
            }
            
            keyStore.setKeyEntry(alias, privateKey, password, chain);
            
            // Fix Logic #218: Atomic write for Keystores
            try (FileOutputStream fos = new FileOutputStream(tempPath.toFile())) {
                keyStore.store(fos, ksPassword);
            }
            secureFile(tempPath);
            Files.move(tempPath, filePath, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            
            privateKeyCache.put(partnerId + ":" + fileName + ":" + alias, privateKey);
        } finally {
            clearPassword(ksPassword);
            Files.deleteIfExists(tempPath);
        }
    }

    public void deletePartnerKeys(String partnerId) {
        validatePartnerId(partnerId);
        if (lockService != null) {
            lockService.executeWithLock(partnerId + ":delete", () -> {
                doDeletePartnerKeys(partnerId);
                return null;
            });
        } else {
            doDeletePartnerKeys(partnerId);
        }
    }

    private void doDeletePartnerKeys(String partnerId) {
        try {
            Path partnerDir = Paths.get(vaultPath, partnerId);
            if (Files.exists(partnerDir)) {
                deleteDirectory(partnerDir);
            }
            privateKeyCache.asMap().keySet().removeIf(k -> k.startsWith(partnerId + ":"));
            log.info("[CLEANUP] Deleted all keys and invalidated cache for partner: {}", partnerId);
        } catch (IOException e) {
            throw new RuntimeException("Failed to delete partner keys: " + partnerId, e);
        }
    }

    private void deleteDirectory(Path dir) throws IOException {
        if (Files.isDirectory(dir)) {
            try (var entries = Files.list(dir)) {
                for (Path entry : entries.toList()) {
                    deleteDirectory(entry);
                }
            }
        }
        Files.deleteIfExists(dir);
    }
}