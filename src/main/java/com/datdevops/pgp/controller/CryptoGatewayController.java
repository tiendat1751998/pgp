package com.datdevops.pgp.controller;

import com.datdevops.pgp.config.CryptoProperties;
import com.datdevops.pgp.dto.request.DecryptRequest;
import com.datdevops.pgp.dto.request.EncryptRequest;
import com.datdevops.pgp.dto.response.DecryptResponse;
import com.datdevops.pgp.dto.response.EncryptResponse;
import com.datdevops.pgp.entity.Partner;
import com.datdevops.pgp.mapper.EntityMapper;
import com.datdevops.pgp.model.SecureEnvelope;
import com.datdevops.pgp.service.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import jakarta.validation.Valid;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.github.benmanes.caffeine.cache.Cache;

@RestController
@RequestMapping("/api/v1/crypto")
public class CryptoGatewayController {

    private static final Logger log = LoggerFactory.getLogger(CryptoGatewayController.class);
    private static final long IDEMPOTENCY_TTL_MINUTES = 10;

    private final SecureEnvelopeService envelopeService;
    private final PartnerService partnerService;
    private final KeyStorageService keyStorageService;
    private final KeyPairGeneratorService keyPairGeneratorService;
    private final RSAKeyPairGeneratorService rsaKeyPairGeneratorService;
    private final EntityMapper entityMapper;
    private final ObjectMapper objectMapper;
    private final CryptoProperties cryptoProperties;

    private final Counter encryptSuccessCounter;
    private final Counter encryptErrorCounter;
    private final Counter decryptSuccessCounter;
    private final Counter decryptErrorCounter;
    private final Timer encryptTimer;
    private final Timer decryptTimer;

    public CryptoGatewayController(
            SecureEnvelopeService envelopeService,
            PartnerService partnerService,
            KeyStorageService keyStorageService,
            KeyPairGeneratorService keyPairGeneratorService,
            RSAKeyPairGeneratorService rsaKeyPairGeneratorService,
            EntityMapper entityMapper,
            CryptoProperties cryptoProperties,
            MeterRegistry meterRegistry) {
        this.envelopeService = envelopeService;
        this.partnerService = partnerService;
        this.keyStorageService = keyStorageService;
        this.keyPairGeneratorService = keyPairGeneratorService;
        this.rsaKeyPairGeneratorService = rsaKeyPairGeneratorService;
        this.entityMapper = entityMapper;
        this.objectMapper = new ObjectMapper();
        this.cryptoProperties = cryptoProperties;

        this.encryptSuccessCounter = Counter.builder("crypto.encrypt.total")
                .tag("status", "success")
                .register(meterRegistry);
        this.encryptErrorCounter = Counter.builder("crypto.encrypt.total")
                .tag("status", "error")
                .register(meterRegistry);
        this.decryptSuccessCounter = Counter.builder("crypto.decrypt.total")
                .tag("status", "success")
                .register(meterRegistry);
        this.decryptErrorCounter = Counter.builder("crypto.decrypt.total")
                .tag("status", "error")
                .register(meterRegistry);
        this.encryptTimer = Timer.builder("crypto.encrypt.duration")
                .publishPercentiles(0.5, 0.95, 0.99)
                .register(meterRegistry);
        this.decryptTimer = Timer.builder("crypto.decrypt.duration")
                .publishPercentiles(0.5, 0.95, 0.99)
                .register(meterRegistry);

        this.idempotencyCache = Caffeine.newBuilder()
                .maximumSize(10000)
                .expireAfterWrite(IDEMPOTENCY_TTL_MINUTES, java.util.concurrent.TimeUnit.MINUTES)
                .build();
    }

    private final Cache<String, String> idempotencyCache;

    @RateLimiter(name = "cryptoApi", fallbackMethod = "rateLimitFallback")
    @PostMapping("/encrypt")
    public ResponseEntity<EncryptResponse> encrypt(
            @Valid @RequestBody EncryptRequest request,
            @RequestHeader(value = "X-Idempotency-Key", required = false) String idempotencyKey) {

        if (idempotencyKey != null && !idempotencyKey.isEmpty()) {
            String cached = idempotencyCache.getIfPresent(idempotencyKey);
            if (cached != null) {
                log.info("Returning cached response for idempotency key: {}", idempotencyKey);
                return ResponseEntity.status(409).body(
                        new EncryptResponse(null, "Duplicate request - use cached response", "IDEMPOTENCY_DUPLICATE"));
            }
        }

        String traceId = UUID.randomUUID().toString();
        MDC.put("traceId", traceId);
        Timer.Sample sample = Timer.start();

        PrivateKey senderPrivateKey = null;
        byte[] senderPrivateKeyBytes = null;
        try {
            String rawPassword = partnerService.getInternalKeystorePassword(request.senderId());
            String keystoreFileName = request.senderId() + "-keystore.p12";
            senderPrivateKey = keyStorageService.getPrivateKeyFromStore(
                request.senderId(), keystoreFileName, "system-key", rawPassword);
            senderPrivateKeyBytes = senderPrivateKey.getEncoded();

            RSAKeyParameters rsaPublicKey;
            String recipientKeyFingerprint = request.recipientKeyFingerprint();

            if (request.recipientRSAPublicKey() != null && !request.recipientRSAPublicKey().isEmpty()) {
                rsaPublicKey = entityMapper.toRSAPublicKey(request.recipientRSAPublicKey());
            } else {
                var partner = partnerService.getPartner(request.recipientId())
                        .orElseThrow(() -> new IllegalArgumentException("Partner not found: " + request.recipientId()));
                rsaPublicKey = entityMapper.toRSAPublicKey(partner.getCustomerRsaPublicKey());
                recipientKeyFingerprint = partner.getKeyFingerprint();
            }

            byte[] payloadBytes = request.payload().getBytes(StandardCharsets.UTF_8);

            String envelopeJson = envelopeService.encryptPayloadWithKeyPair(
                payloadBytes,
                request.payloadType(),
                request.senderId(),
                request.senderKeyFingerprint(),
                request.recipientId(),
                recipientKeyFingerprint,
                senderPrivateKeyBytes,
                rsaPublicKey
            );

            SecureEnvelope envelope = objectMapper.readValue(envelopeJson, SecureEnvelope.class);
            String encryptedEnvelopeBase64 = entityMapper.toBase64(envelopeJson);
            EncryptResponse response = entityMapper.toEncryptResponse(envelope, encryptedEnvelopeBase64);

            encryptSuccessCounter.increment();
            log.info("[ENCRYPT_SUCCESS] traceId={} sender={} recipient={} payloadType={}",
                    traceId, request.senderId(), request.recipientId(), request.payloadType());

            if (idempotencyKey != null && !idempotencyKey.isEmpty()) {
                idempotencyCache.put(idempotencyKey, envelopeJson);
            }

            return ResponseEntity.ok(response);

        } catch (SecurityException e) {
            encryptErrorCounter.increment();
            log.warn("[SECURITY] Encrypt blocked | traceId={} sender={} recipient={} reason={}",
                    traceId, request.senderId(), request.recipientId(), e.getMessage());
            return ResponseEntity.status(403).build();
        } catch (Exception e) {
            encryptErrorCounter.increment();
            log.error("[ERROR] Encrypt failed | traceId={} sender={} recipient={}",
                    traceId, request.senderId(), request.recipientId(), e);
            return ResponseEntity.internalServerError().build();
        } finally {
            if (senderPrivateKeyBytes != null) java.util.Arrays.fill(senderPrivateKeyBytes, (byte) 0);
            sample.stop(encryptTimer);
            MDC.clear();
        }
    }

    @RateLimiter(name = "cryptoApi", fallbackMethod = "rateLimitFallback")
    @PostMapping("/decrypt")
    public ResponseEntity<DecryptResponse> decrypt(
            @Valid @RequestBody DecryptRequest request,
            @RequestHeader(value = "X-Idempotency-Key", required = false) String idempotencyKey) {

        if (idempotencyKey != null && !idempotencyKey.isEmpty()) {
            String cached = idempotencyCache.getIfPresent(idempotencyKey);
            if (cached != null) {
                log.info("Returning cached response for idempotency key: {}", idempotencyKey);
                return ResponseEntity.status(409).body(
                        new DecryptResponse("IDEMPOTENCY_DUPLICATE", "Duplicate request - use cached response"));
            }
        }

        String traceId = UUID.randomUUID().toString();
        MDC.put("traceId", traceId);
        Timer.Sample sample = Timer.start();

        String partnerId = null;
        try {
            String envelopeJson = new String(entityMapper.fromBase64(request.envelope()), StandardCharsets.UTF_8);
            SecureEnvelope envelope = objectMapper.readValue(envelopeJson, SecureEnvelope.class);

            partnerId = envelope.getRecipient().getId();
            final String finalPartnerId = partnerId;
            partnerService.getPartner(partnerId)
                    .orElseThrow(() -> new IllegalArgumentException("Recipient partner not found: " + finalPartnerId));

            String rawPassword = partnerService.getInternalKeystorePassword(partnerId);
            String keystoreFileName = partnerId + "-keystore.p12";
            PrivateKey privateKey = keyStorageService.getPrivateKeyFromStore(
                partnerId, keystoreFileName, "system-key", rawPassword);

            RSAKeyParameters rsaPrivateKey = entityMapper.toRSAPrivateKey(privateKey);

            byte[] senderPublicKey;
            if (request.senderPublicKey() != null && !request.senderPublicKey().isEmpty()) {
                senderPublicKey = entityMapper.fromBase64(request.senderPublicKey());
            } else {
                var senderPartner = partnerService.getPartner(envelope.getSender().getId())
                        .orElseThrow(() -> new IllegalArgumentException("Sender not found: " + envelope.getSender().getId()));
                senderPublicKey = entityMapper.fromBase64(senderPartner.getCustomerEd25519PublicKey());
            }

            byte[] decryptedPayload = envelopeService.decryptPayload(envelopeJson, rsaPrivateKey, senderPublicKey);
            String payload = new String(decryptedPayload, StandardCharsets.UTF_8);

            decryptSuccessCounter.increment();
            log.info("[DECRYPT_SUCCESS] traceId={} sender={} recipient={} payloadType={}",
                    traceId, envelope.getSender().getId(), partnerId, envelope.getMessageType());

            return ResponseEntity.ok(new DecryptResponse(envelope.getMessageType(), payload));

        } catch (SecurityException e) {
            decryptErrorCounter.increment();
            log.warn("[SECURITY] Decrypt blocked | traceId={} partnerId={} reason={}",
                    traceId, partnerId, e.getMessage());
            return ResponseEntity.status(403).build();
        } catch (Exception e) {
            decryptErrorCounter.increment();
            log.error("[ERROR] Decrypt failed | traceId={} partnerId={}", traceId, partnerId, e);
            return ResponseEntity.internalServerError().build();
        } finally {
            sample.stop(decryptTimer);
            MDC.clear();
        }
    }

    @PostMapping("/keypair")
    public ResponseEntity<Map<String, String>> generateKeyPair() {
        try {
            var ed25519KeyPair = keyPairGeneratorService.generateEd25519KeyPair();
            byte[] ed25519PrivateKey = keyPairGeneratorService.getEd25519PrivateKey(ed25519KeyPair).getEncoded();
            byte[] ed25519PublicKey = keyPairGeneratorService.getEd25519PublicKey(ed25519KeyPair).getEncoded();

            var rsaKeyPair = rsaKeyPairGeneratorService.generateRSAKeyPair();

            Map<String, String> response = new HashMap<>();
            response.put("ed25519PrivateKey", entityMapper.toBase64(ed25519PrivateKey));
            response.put("ed25519PublicKey", entityMapper.toBase64(ed25519PublicKey));
            response.put("rsaPublicKey", rsaKeyPairGeneratorService.getBase64PublicKey(rsaKeyPair));
            response.put("rsaPrivateKey", rsaKeyPairGeneratorService.getBase64PrivateKey(rsaKeyPair));

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> status = new HashMap<>();
        status.put("status", "UP");
        status.put("service", "crypto-gateway");

        Map<String, Object> cache = new HashMap<>();
        cache.put("partnerSize", partnerService.getCacheSize());
        cache.put("keySize", keyStorageService.getCacheSize());
        cache.put("idempotencySize", idempotencyCache.estimatedSize());
        status.put("cache", cache);

        Map<String, Object> performance = new HashMap<>();
        Runtime runtime = Runtime.getRuntime();
        performance.put("availableProcessors", runtime.availableProcessors());
        performance.put("freeMemoryMB", runtime.freeMemory() / 1024 / 1024);
        performance.put("totalMemoryMB", runtime.totalMemory() / 1024 / 1024);
        performance.put("maxMemoryMB", runtime.maxMemory() / 1024 / 1024);
        performance.put("encryptCount", encryptSuccessCounter.count());
        performance.put("decryptCount", decryptSuccessCounter.count());
        status.put("performance", performance);

        status.put("timestamp", System.currentTimeMillis());

        return ResponseEntity.ok(status);
    }

    public ResponseEntity<EncryptResponse> rateLimitFallback(EncryptRequest request, Throwable t) {
        return ResponseEntity.status(429).body(
                new EncryptResponse(null, "Rate limit exceeded. Please try again later.", "RATE_LIMIT_EXCEEDED"));
    }

    public ResponseEntity<DecryptResponse> rateLimitFallback(DecryptRequest request, Throwable t) {
        return ResponseEntity.status(429).body(
                new DecryptResponse("RATE_LIMIT_EXCEEDED", "Rate limit exceeded. Please try again later."));
    }
}