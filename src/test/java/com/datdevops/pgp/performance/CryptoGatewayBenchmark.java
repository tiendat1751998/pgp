package com.datdevops.pgp.performance;

import com.datdevops.pgp.service.EncryptionService;
import com.datdevops.pgp.service.PartnerService;
import com.datdevops.pgp.service.KeyStorageService;
import com.datdevops.pgp.service.AuditService;
import com.datdevops.pgp.repository.AuditRepository;
import org.openjdk.jmh.annotations.*;
import org.mockito.Mockito;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.UUID;
import java.util.concurrent.*;

@State(Scope.Thread)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
public class CryptoGatewayBenchmark {

    @Param({"1000", "5000"})
    private int partners;

    private EncryptionService encryptionService;
    private PartnerService partnerService;
    private KeyStorageService keyStorageService;
    private AuditService auditService;

    private byte[] testSessionKey;
    private byte[] associatedData;
    private String[] partnerIds;

    @Setup
    public void setup() throws Exception {
        encryptionService = new EncryptionService();
        keyStorageService = new KeyStorageService(null);
        
        auditService = new AuditService();
        
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        
        // Mock all dependencies for PartnerService for pure JMH benchmark
        partnerService = new PartnerService(
            Mockito.mock(com.datdevops.pgp.repository.PartnerRepository.class),
            Mockito.mock(com.datdevops.pgp.service.SecretEncryptionService.class),
            keyStorageService,
            Mockito.mock(com.datdevops.pgp.service.KeyPairGeneratorService.class),
            Mockito.mock(com.datdevops.pgp.service.RSAKeyPairGeneratorService.class),
            encryptionService,
            Mockito.mock(com.datdevops.pgp.mapper.EntityMapper.class)
        );
        
        partnerIds = new String[partners];
        for (int i = 0; i < partners; i++) {
            partnerIds[i] = "PARTNER-" + i;
        }
        
        testSessionKey = new byte[32];
        associatedData = new byte[16];
        new java.security.SecureRandom().nextBytes(testSessionKey);
        new java.security.SecureRandom().nextBytes(associatedData);
    }

    @Benchmark
    public void benchmarkEncryptDecrypt() throws Exception {
        EncryptionService.EncryptionResult result = encryptionService.encrypt(testSessionKey, testSessionKey, associatedData);
        byte[] decrypted = encryptionService.decrypt(result.getCiphertext(), testSessionKey, result.getNonce(), result.getMac(), associatedData);
    }

    @Benchmark
    public void benchmarkPartnerLookup() {
        String partnerId = partnerIds[ThreadLocalRandom.current().nextInt(partners)];
        partnerService.getPartner(partnerId);
    }

    @Benchmark
    public void benchmarkAuditLogging() {
        String correlationId = UUID.randomUUID().toString();
        auditService.logEncrypt(correlationId, "SENDER", "RECEIVER", "ISO8583", true);
    }

    @Benchmark
    public void benchmarkCacheLookup() throws Exception {
        String partnerId = partnerIds[ThreadLocalRandom.current().nextInt(partners)];
        // This will attempt to lookup from cache or disk (disk mock will fail, so cache only)
        try {
            keyStorageService.getPrivateKeyFromStore(partnerId, partnerId + "-keystore.p12", "system-key", "dummy");
        } catch (Exception e) {
            // expected since file doesn't exist in JMH context, but measures cache miss overhead
        }
    }
}