package com.datdevops.pgp.envelope;

import com.datdevops.pgp.config.CryptoConfig;
import com.datdevops.pgp.model.SecureEnvelope;
import com.datdevops.pgp.service.*;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

public class Phase3SecureEnvelopeTest {

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
            objectMapper
        );
    }

    @Test
    public void testSecureEnvelopeCreation() {
        SecureEnvelope envelope = SecureEnvelope.builder()
            .messageType("TEXT")
            .sender("BANK_A", "ABCD1234EFGH5678")
            .recipient("BANK_B", "WXYZ9876QRST5432")
            .build();
        
        assertNotNull(envelope);
        assertNotNull(envelope.getMessageId());
        assertNotNull(envelope.getTimestamp());
        assertEquals("TEXT", envelope.getMessageType());
        assertEquals("BANK_A", envelope.getSender().getId());
        assertEquals("AES-256-GCM", envelope.getAlgorithm().encryption);
        
        System.out.println("SecureEnvelope Creation: SUCCESS");
    }

    @Test
    public void testSecureEnvelopeSerialization() {
        SecureEnvelope envelope = SecureEnvelope.builder()
            .messageType("JSON")
            .sender("BANK_A", "KEY-FP")
            .recipient("BANK_B", "KEY-FP")
            .build();
        
        envelope.setEncryptedPayload("dGhpc0lzRW5jcnlwdGVk");
        envelope.setEncryptedSessionKey("c2Vzc2lvbktleQ==");
        
        String json = null;
        try {
            json = objectMapper.writeValueAsString(envelope);
        } catch (Exception e) {
            fail("Serialization failed");
        }
        
        assertNotNull(json);
        assertTrue(json.contains("BANK_A"));
        
        System.out.println("SecureEnvelope Serialization: SUCCESS");
    }

    @Test
    public void testEnvelopeWithGenericPayload() throws Exception {
        var senderKeyPair = keyPairGeneratorService.generateEd25519KeyPair();
        byte[] senderPrivateKey = keyPairGeneratorService.getEd25519PrivateKey(senderKeyPair).getEncoded();
        
        var rsaKeyPair = rsaKeyPairGeneratorService.generateRSAKeyPair();
        RSAKeyParameters rsaPublicKey = rsaKeyPairGeneratorService.getPublicKey(rsaKeyPair);

        String payload = "{\"test\": \"data\"}";
        byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
        
        SecureEnvelopeService envelopeService = createService();
        
        String envelopeJson = envelopeService.encryptPayloadWithKeyPair(
            payloadBytes,
            "JSON",
            "BANK_A",
            "SENDER-FP",
            "BANK_B",
            "RECIP-FP",
            senderPrivateKey,
            rsaPublicKey
        );
        
        assertNotNull(envelopeJson);
        
        RSAKeyParameters rsaPrivateKey = rsaKeyPairGeneratorService.getPrivateKey(rsaKeyPair);
        
        byte[] decryptedPayload = envelopeService.decryptPayload(
            envelopeJson,
            rsaPrivateKey,
            keyPairGeneratorService.getEd25519PublicKey(senderKeyPair).getEncoded()
        );
        
        assertEquals(payload, new String(decryptedPayload, StandardCharsets.UTF_8));
        
        System.out.println("Envelope Generic Payload: SUCCESS");
    }

    @Test
    public void testMultipleMessages() throws Exception {
        var senderKeyPair = keyPairGeneratorService.generateEd25519KeyPair();
        byte[] senderPrivateKey = keyPairGeneratorService.getEd25519PrivateKey(senderKeyPair).getEncoded();
        
        var rsaKeyPair = rsaKeyPairGeneratorService.generateRSAKeyPair();
        RSAKeyParameters rsaPublicKey = rsaKeyPairGeneratorService.getPublicKey(rsaKeyPair);
        RSAKeyParameters rsaPrivateKey = rsaKeyPairGeneratorService.getPrivateKey(rsaKeyPair);
        
        SecureEnvelopeService envelopeService = createService();
        
        for (int i = 0; i < 5; i++) {
            String payload = "Message #" + i;
            String envelopeJson = envelopeService.encryptPayloadWithKeyPair(
                payload.getBytes(StandardCharsets.UTF_8),
                "TEXT",
                "BANK_A", "FP", "BANK_B", "FP",
                senderPrivateKey, rsaPublicKey
            );
            
            byte[] decrypted = envelopeService.decryptPayload(
                envelopeJson, rsaPrivateKey, 
                keyPairGeneratorService.getEd25519PublicKey(senderKeyPair).getEncoded()
            );
            
            assertEquals(payload, new String(decrypted, StandardCharsets.UTF_8));
        }
        
        System.out.println("Multiple Messages: SUCCESS");
    }

    @Test
    public void testEnvelopeMetadata() throws Exception {
        var senderKeyPair = keyPairGeneratorService.generateEd25519KeyPair();
        byte[] senderPrivateKey = keyPairGeneratorService.getEd25519PrivateKey(senderKeyPair).getEncoded();
        
        var rsaKeyPair = rsaKeyPairGeneratorService.generateRSAKeyPair();
        RSAKeyParameters rsaPublicKey = rsaKeyPairGeneratorService.getPublicKey(rsaKeyPair);

        String payload = "metadata-test";
        
        SecureEnvelopeService envelopeService = createService();
        
        String envelopeJson = envelopeService.encryptPayloadWithKeyPair(
            payload.getBytes(StandardCharsets.UTF_8),
            "RAW",
            "BANK_A", "ABCD1234", "BANK_B", "WXYZ5678",
            senderPrivateKey, rsaPublicKey
        );
        
        SecureEnvelope envelope = objectMapper.readValue(envelopeJson, SecureEnvelope.class);
        
        assertEquals("RAW", envelope.getMessageType());
        assertEquals("BANK_A", envelope.getSender().getId());
        assertEquals("ABCD1234", envelope.getSender().getKeyFingerprint());
        assertNotNull(envelope.getCorrelationId());
        
        System.out.println("Envelope Metadata: SUCCESS");
    }
}