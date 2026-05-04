package com.datdevops.pgp.crypto;

import com.datdevops.pgp.config.CryptoConfig;
import com.datdevops.pgp.service.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

public class Phase1CoreCryptographyTest {

    @BeforeAll
    static void setup() {
        new CryptoConfig();
    }

    @Test
    public void testEd25519KeyPairGeneration() {
        KeyPairGeneratorService keyGen = new KeyPairGeneratorService();
        
        var keyPair = keyGen.generateEd25519KeyPair();
        
        byte[] privateKey = keyGen.getEd25519PrivateKey(keyPair).getEncoded();
        byte[] publicKey = keyGen.getEd25519PublicKey(keyPair).getEncoded();
        
        assertNotNull(privateKey);
        assertNotNull(publicKey);
        assertTrue(privateKey.length > 0);
        assertTrue(publicKey.length > 0);
        
        System.out.println("Ed25519 Key Pair Generated:");
        System.out.println("  Private Key: " + Base64.getEncoder().encodeToString(privateKey).substring(0, 32) + "...");
        System.out.println("  Public Key: " + Base64.getEncoder().encodeToString(publicKey).substring(0, 32) + "...");
    }

    @Test
    public void testRSAKeyPairGeneration() throws Exception {
        RSAKeyPairGeneratorService rsaKeyGen = new RSAKeyPairGeneratorService();
        
        var keyPair = rsaKeyGen.generateRSAKeyPair();
        
        String rsaPublicKey = rsaKeyGen.getBase64PublicKey(keyPair);
        String rsaPrivateKey = rsaKeyGen.getBase64PrivateKey(keyPair);
        
        assertNotNull(rsaPublicKey);
        assertNotNull(rsaPrivateKey);
        assertTrue(rsaPublicKey.length() >= 100);
        assertTrue(rsaPrivateKey.length() >= 100);
        
        System.out.println("RSA Key Pair Generated:");
        System.out.println("  Public Key Length: " + rsaPublicKey.length());
        System.out.println("  Private Key Length: " + rsaPrivateKey.length());
    }

    @Test
    public void testSignAndVerifyEd25519() throws Exception {
        KeyPairGeneratorService keyGen = new KeyPairGeneratorService();
        SigningService signingService = new SigningService();
        SignatureVerificationService verificationService = new SignatureVerificationService();
        
        var keyPair = keyGen.generateEd25519KeyPair();
        byte[] privateKey = keyGen.getEd25519PrivateKey(keyPair).getEncoded();
        byte[] publicKey = keyGen.getEd25519PublicKey(keyPair).getEncoded();
        
        String message = "Transfer 1000000 VND from Account A to Account B";
        byte[] messageBytes = message.getBytes();
        
        byte[] signature = signingService.sign(messageBytes, 
            new org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters(privateKey, 0));
        
        assertNotNull(signature);
        assertTrue(signature.length > 0);
        
        boolean verified = verificationService.verify(messageBytes, signature, 
            new org.bouncycastle.crypto.params.Ed25519PublicKeyParameters(publicKey, 0));
        
        assertTrue(verified);
        
        System.out.println("Ed25519 Sign/Verify: SUCCESS");
    }

    @Test
    public void testAES256GCMEncryptionDecryption() throws Exception {
        EncryptionService encryptionService = new EncryptionService();
        
        byte[] plaintext = "Sensitive payment data".getBytes();
        byte[] key = new byte[32];
        new java.security.SecureRandom().nextBytes(key);
        byte[] associatedData = "AUTH".getBytes();
        
        var result = encryptionService.encrypt(plaintext, key, associatedData);
        
        assertNotNull(result.getCiphertext());
        assertNotNull(result.getNonce());
        assertNotNull(result.getMac());
        
        byte[] decrypted = encryptionService.decrypt(
            result.getCiphertext(), 
            key, 
            result.getNonce(), 
            result.getMac(), 
            associatedData);
        
        assertArrayEquals(plaintext, decrypted);
        
        System.out.println("AES-256-GCM Encrypt/Decrypt: SUCCESS");
    }

    @Test
    public void testRSAEncryptionDecryption() throws Exception {
        RSAKeyPairGeneratorService rsaKeyGen = new RSAKeyPairGeneratorService();
        EncryptionService encryptionService = new EncryptionService();
        
        var keyPair = rsaKeyGen.generateRSAKeyPair();
        var rsaPublicKey = rsaKeyGen.getPublicKey(keyPair);
        var rsaPrivateKey = rsaKeyGen.getPrivateKey(keyPair);
        
        byte[] sessionKey = new byte[32];
        new java.security.SecureRandom().nextBytes(sessionKey);
        
        byte[] encryptedSessionKey = encryptionService.encryptSessionKey(sessionKey, rsaPublicKey);
        
        assertNotNull(encryptedSessionKey);
        assertTrue(encryptedSessionKey.length > sessionKey.length);
        
        byte[] decryptedSessionKey = encryptionService.decryptSessionKey(encryptedSessionKey, rsaPrivateKey);
        
        assertArrayEquals(sessionKey, decryptedSessionKey);
        
        System.out.println("RSA-OAEP Encrypt/Decrypt Session Key: SUCCESS");
    }

    @Test
    public void testHybridEncryptionDecryption() throws Exception {
        KeyPairGeneratorService keyGen = new KeyPairGeneratorService();
        RSAKeyPairGeneratorService rsaKeyGen = new RSAKeyPairGeneratorService();
        EncryptionService encryptionService = new EncryptionService();
        
        var ed25519KeyPair = keyGen.generateEd25519KeyPair();
        byte[] senderPrivateKey = keyGen.getEd25519PrivateKey(ed25519KeyPair).getEncoded();
        
        var rsaKeyPair = rsaKeyGen.generateRSAKeyPair();
        var rsaPublicKey = rsaKeyGen.getPublicKey(rsaKeyPair);
        var rsaPrivateKey = rsaKeyGen.getPrivateKey(rsaKeyPair);
        
        String message = "ISO8583:0200|POS001|Merchant123|100000";
        byte[] payload = message.getBytes();
        
        byte[] sessionKey = new byte[32];
        new java.security.SecureRandom().nextBytes(sessionKey);
        
        var encryptResult = encryptionService.encrypt(payload, sessionKey, "ISO8583".getBytes());
        
        byte[] encryptedSessionKey = encryptionService.encryptSessionKey(sessionKey, rsaPublicKey);
        
        byte[] decryptedSessionKey = encryptionService.decryptSessionKey(encryptedSessionKey, rsaPrivateKey);
        
        byte[] decryptedPayload = encryptionService.decrypt(
            encryptResult.getCiphertext(),
            decryptedSessionKey,
            encryptResult.getNonce(),
            encryptResult.getMac(),
            "ISO8583".getBytes()
        );
        
        assertArrayEquals(payload, decryptedPayload);
        
        System.out.println("Hybrid Encryption (RSA + AES-GCM): SUCCESS");
    }
}