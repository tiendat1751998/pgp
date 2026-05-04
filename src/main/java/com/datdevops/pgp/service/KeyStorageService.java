package com.datdevops.pgp.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.resilience4j.retry.annotation.Retry;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.bulkhead.annotation.Bulkhead;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import jakarta.annotation.PostConstruct;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

@Service
public class KeyStorageService {

    @Value("${app.key-store-path:./vault/}")
    private String vaultPath;

    @Value("${app.keystore.password:changeit}")
    private String keystorePassword;

    private final Cache<String, PrivateKey> privateKeyCache;
    private final DistributedLockService lockService;

    public KeyStorageService(DistributedLockService lockService) {
        this.lockService = lockService != null ? lockService : null;
        this.privateKeyCache = Caffeine.newBuilder()
                .maximumSize(1000)
                .expireAfterAccess(30, TimeUnit.MINUTES)
                .build();
    }

private static final Pattern SAFE_PARTNER_ID = Pattern.compile("^[a-zA-Z0-9_-]+$");

    @PostConstruct
    public void init() throws IOException {
        Path vault = Paths.get(vaultPath);
        if (!Files.exists(vault)) {
            Files.createDirectories(vault);
        }
    }

    private void validatePartnerId(String partnerId) {
        if (partnerId == null || !SAFE_PARTNER_ID.matcher(partnerId).matches()) {
            throw new IllegalArgumentException("Invalid partnerId: must be alphanumeric, underscore or hyphen only");
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

    // --- Organized File Operations ---

    public void savePartnerKey(String partnerId, String fileName, byte[] keyData) throws IOException {
        validatePartnerId(partnerId);
        Path partnerDir = getPartnerPath(partnerId);
        Path filePath = partnerDir.resolve(fileName);
        Files.write(filePath, keyData);
    }

    public byte[] loadPartnerKey(String partnerId, String fileName) throws IOException {
        Path filePath = getPartnerPath(partnerId).resolve(fileName);
        if (!Files.exists(filePath)) {
            throw new IOException("Key file not found for partner " + partnerId + ": " + fileName);
        }
        return Files.readAllBytes(filePath);
    }

    // --- Vault-style KeyStore Operations ---

    private String getKeystoreFileName(String partnerId) {
        return partnerId + "-keystore.p12";
    }

    @Retry(name = "keyStorage")
    @CircuitBreaker(name = "keyStorage", fallbackMethod = "loadPartnerKeyStoreFallback")
    public KeyStore loadPartnerKeyStore(String partnerId, String fileName) throws Exception {
        if (fileName == null || fileName.isEmpty()) {
            fileName = getKeystoreFileName(partnerId);
        }
        Path filePath = getPartnerPath(partnerId).resolve(fileName);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(filePath.toFile())) {
            keyStore.load(fis, keystorePassword.toCharArray());
        }
        return keyStore;
    }

    @Retry(name = "keyStorage")
    @Bulkhead(name = "keyAccess")
    public PrivateKey getPrivateKeyFromStore(String partnerId, String fileName, String alias, String password) throws Exception {
        String cacheKey = partnerId + ":" + fileName + ":" + alias;
        
        // 1. Check RAM Cache First (to prevent disk I/O bottleneck)
        PrivateKey cachedKey = privateKeyCache.getIfPresent(cacheKey);
        if (cachedKey != null) {
            return cachedKey;
        }
        
        // 2. Fallback to Disk Vault
        KeyStore keyStore = loadPartnerKeyStore(partnerId, fileName);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
        
        if (privateKey != null) {
            privateKeyCache.put(cacheKey, privateKey);
        }
        
        return privateKey;
    }

    @Retry(name = "keyStorage")
    public void savePartnerKeyStore(String partnerId, String fileName, String alias, PrivateKey privateKey, Certificate[] chain, String password) throws Exception {
        if (lockService != null) {
            String lockResource = partnerId + ":" + fileName;
            lockService.executeWithLock(lockResource, () -> {
                doSavePartnerKeyStore(partnerId, fileName, alias, privateKey, chain, password);
                return null;
            });
        } else {
            doSavePartnerKeyStore(partnerId, fileName, alias, privateKey, chain, password);
        }
    }

    private void doSavePartnerKeyStore(String partnerId, String fileName, String alias, PrivateKey privateKey, Certificate[] chain, String password) throws Exception {
        Path partnerDir = getPartnerPath(partnerId);
        Path filePath = partnerDir.resolve(fileName);
        
        KeyStore keyStore;
        if (Files.exists(filePath)) {
            keyStore = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(filePath.toFile())) {
                keyStore.load(fis, keystorePassword.toCharArray());
            }
        } else {
            keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, keystorePassword.toCharArray());
        }

        keyStore.setKeyEntry(alias, privateKey, password.toCharArray(), chain);
        
        try (FileOutputStream fos = new FileOutputStream(filePath.toFile())) {
            keyStore.store(fos, keystorePassword.toCharArray());
        }
        
        String cacheKey = partnerId + ":" + fileName + ":" + alias;
        privateKeyCache.put(cacheKey, privateKey);
    }

    // --- Helpers ---

    public void clearCache() {
        privateKeyCache.invalidateAll();
    }

    public long getCacheSize() {
        return privateKeyCache.estimatedSize();
    }

    public void deletePartnerKeys(String partnerId) {
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

    private KeyStore loadPartnerKeyStoreFallback(String partnerId, String fileName, Throwable t) {
        throw new RuntimeException("Failed to load keystore for partner: " + partnerId + ". Cause: " + t.getMessage());
    }
}