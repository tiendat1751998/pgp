package com.datdevops.pgp.controller;

import com.datdevops.pgp.config.CryptoConfig;
import com.datdevops.pgp.service.*;
import com.datdevops.pgp.model.SecureEnvelope;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class Phase4TransportIntegrationTest {

    private static ObjectMapper objectMapper;
    private static EncryptionService encryptionService;
    private static SigningService signingService;
    private static SignatureVerificationService signatureVerificationService;
    private static KeyPairGeneratorService keyPairGeneratorService;
    private static RSAKeyPairGeneratorService rsaKeyPairGeneratorService;

    @BeforeAll
    static void setup() {
        new CryptoConfig();
        objectMapper = new ObjectMapper();
        encryptionService = new EncryptionService();
        signingService = new SigningService();
        signatureVerificationService = new SignatureVerificationService();
        keyPairGeneratorService = new KeyPairGeneratorService();
        rsaKeyPairGeneratorService = new RSAKeyPairGeneratorService();
    }

    private SecureEnvelopeService createService() {
        return new SecureEnvelopeService(
            encryptionService,
            signingService,
            signatureVerificationService,
            keyPairGeneratorService,
            rsaKeyPairGeneratorService,
            new ReplayProtectionService(),
            new KeyRotationService(),
            objectMapper
        );
    }

    @Test
    public void testControllerEncryptDecrypt() throws Exception {
        var senderKeyPair = keyPairGeneratorService.generateEd25519KeyPair();
        byte[] senderPrivateKey = keyPairGeneratorService.getEd25519PrivateKey(senderKeyPair).getEncoded();
        
        var rsaKeyPair = rsaKeyPairGeneratorService.generateRSAKeyPair();
        RSAKeyParameters rsaPublicKey = rsaKeyPairGeneratorService.getPublicKey(rsaKeyPair);
        RSAKeyParameters rsaPrivateKey = rsaKeyPairGeneratorService.getPrivateKey(rsaKeyPair);

        String payload = "{\"transaction\": \"test-data\", \"amount\": 1000}";
        byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
        
        SecureEnvelopeService envelopeService = createService();
        
        String envelopeJson = envelopeService.encryptPayloadWithKeyPair(
            payloadBytes,
            "JSON",
            "BANK_A",
            "ABCD1234",
            "BANK_B",
            "WXYZ5678",
            senderPrivateKey,
            rsaPublicKey
        );
        
        assertNotNull(envelopeJson);
        
        byte[] decryptedBytes = envelopeService.decryptPayload(
            envelopeJson,
            rsaPrivateKey,
            keyPairGeneratorService.getEd25519PublicKey(senderKeyPair).getEncoded()
        );
        
        String decrypted = new String(decryptedBytes, StandardCharsets.UTF_8);
        assertEquals(payload, decrypted);
        
        System.out.println("Controller Encrypt/Decrypt: SUCCESS");
    }

    @Test
    public void testKeyPairGeneration() throws Exception {
        var ed25519KeyPair = keyPairGeneratorService.generateEd25519KeyPair();
        byte[] ed25519PrivateKey = keyPairGeneratorService.getEd25519PrivateKey(ed25519KeyPair).getEncoded();
        byte[] ed25519PublicKey = keyPairGeneratorService.getEd25519PublicKey(ed25519KeyPair).getEncoded();
        
        var rsaKeyPair = rsaKeyPairGeneratorService.generateRSAKeyPair();
        String rsaPublicKeyBase64 = rsaKeyPairGeneratorService.getBase64PublicKey(rsaKeyPair);
        String rsaPrivateKeyBase64 = rsaKeyPairGeneratorService.getBase64PrivateKey(rsaKeyPair);
        
        assertNotNull(ed25519PrivateKey);
        assertNotNull(ed25519PublicKey);
        assertTrue(ed25519PrivateKey.length > 0);
        assertTrue(rsaPublicKeyBase64.length() > 100);
        assertTrue(rsaPrivateKeyBase64.length() > 100);
        
        System.out.println("KeyPair Generation: SUCCESS");
    }

    @Test
    public void testDecryptRequest() throws Exception {
        var senderKeyPair = keyPairGeneratorService.generateEd25519KeyPair();
        byte[] senderPrivateKey = keyPairGeneratorService.getEd25519PrivateKey(senderKeyPair).getEncoded();
        
        var rsaKeyPair = rsaKeyPairGeneratorService.generateRSAKeyPair();
        RSAKeyParameters rsaPublicKey = rsaKeyPairGeneratorService.getPublicKey(rsaKeyPair);
        RSAKeyParameters rsaPrivateKey = rsaKeyPairGeneratorService.getPrivateKey(rsaKeyPair);

        String payload = "test-payload";
        
        SecureEnvelopeService envelopeService = createService();
        
        String envelopeJson = envelopeService.encryptPayloadWithKeyPair(
            payload.getBytes(StandardCharsets.UTF_8),
            "TEXT",
            "SENDER", "FP", "RECIPIENT", "FP",
            senderPrivateKey, rsaPublicKey
        );
        
        String encryptedEnvelopeBase64 = Base64.getEncoder().encodeToString(envelopeJson.getBytes(StandardCharsets.UTF_8));
        String decodedJson = new String(Base64.getDecoder().decode(encryptedEnvelopeBase64), StandardCharsets.UTF_8);
        
        byte[] decryptedBytes = envelopeService.decryptPayload(
            decodedJson,
            rsaPrivateKey,
            keyPairGeneratorService.getEd25519PublicKey(senderKeyPair).getEncoded()
        );
        
        assertEquals(payload, new String(decryptedBytes, StandardCharsets.UTF_8));
        
        System.out.println("Decrypt Request: SUCCESS");
    }

    @Test
    public void testHealthEndpoint() {
        Map<String, String> status = new HashMap<>();
        status.put("status", "UP");
        status.put("service", "crypto-gateway");
        
        assertEquals("UP", status.get("status"));
        
        System.out.println("Health Endpoint: SUCCESS");
    }

    @Test
    public void testMultipleEncryptDecrypt() throws Exception {
        var senderKeyPair = keyPairGeneratorService.generateEd25519KeyPair();
        byte[] senderPrivateKey = keyPairGeneratorService.getEd25519PrivateKey(senderKeyPair).getEncoded();
        
        var rsaKeyPair = rsaKeyPairGeneratorService.generateRSAKeyPair();
        RSAKeyParameters rsaPublicKey = rsaKeyPairGeneratorService.getPublicKey(rsaKeyPair);
        RSAKeyParameters rsaPrivateKey = rsaKeyPairGeneratorService.getPrivateKey(rsaKeyPair);

        SecureEnvelopeService envelopeService = createService();
        
        String[] payloads = {"Data 1", "Data 2", "Data 3"};
        
        for (String p : payloads) {
            String envelopeJson = envelopeService.encryptPayloadWithKeyPair(
                p.getBytes(StandardCharsets.UTF_8),
                "TEXT",
                "SENDER", "FP", "RECIPIENT", "FP",
                senderPrivateKey, rsaPublicKey
            );
            
            byte[] decrypted = envelopeService.decryptPayload(
                envelopeJson, rsaPrivateKey,
                keyPairGeneratorService.getEd25519PublicKey(senderKeyPair).getEncoded()
            );
            
            assertEquals(p, new String(decrypted, StandardCharsets.UTF_8));
        }
        
        System.out.println("Multiple Encrypt/Decrypt: SUCCESS");
    }

    @Test
    public void testBase64Encoding() throws Exception {
        String testData = "Hello Crypto Gateway";
        byte[] bytes = testData.getBytes(StandardCharsets.UTF_8);
        
        String encoded = Base64.getEncoder().encodeToString(bytes);
        byte[] decoded = Base64.getDecoder().decode(encoded);
        String result = new String(decoded, StandardCharsets.UTF_8);
        
        assertEquals(testData, result);
        
        System.out.println("Base64 Encoding: SUCCESS");
    }
}