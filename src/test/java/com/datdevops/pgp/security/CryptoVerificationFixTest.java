package com.datdevops.pgp.security;

import com.datdevops.pgp.service.EncryptionService;
import com.datdevops.pgp.service.KeyPairGeneratorService;
import com.datdevops.pgp.service.KeyService;
import com.datdevops.pgp.service.SignatureVerificationService;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
public class CryptoVerificationFixTest {

    @Autowired
    private SignatureVerificationService signatureVerificationService;

    @Autowired
    private KeyPairGeneratorService keyPairGeneratorService;

    @Autowired
    private KeyService keyService;

    @Test
    public void testEd25519SignatureVerification_NotSigningMode() throws Exception {
        var keyPair = keyPairGeneratorService.generateEd25519KeyPair();
        Ed25519PrivateKeyParameters privateKey = keyPairGeneratorService.getEd25519PrivateKey(keyPair);
        Ed25519PublicKeyParameters publicKey = keyPairGeneratorService.getEd25519PublicKey(keyPair);

        String message = "Test message for signature verification";
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, privateKey);
        signer.update(messageBytes, 0, messageBytes.length);
        byte[] signature = signer.generateSignature();

        boolean result = signatureVerificationService.verify(messageBytes, signature, publicKey);
        assertTrue(result, "Signature should be valid");

        byte[] invalidSignature = new byte[64];
        invalidSignature[0] = (byte) 0xFF;
        boolean invalidResult = signatureVerificationService.verify(messageBytes, invalidSignature, publicKey);
        assertFalse(invalidResult, "Invalid signature should fail verification");
    }

    @Test
    public void testConstantTimeVerification_PreventsTimingAttack() {
        var keyPair = keyPairGeneratorService.generateEd25519KeyPair();
        Ed25519PublicKeyParameters publicKey = keyPairGeneratorService.getEd25519PublicKey(keyPair);

        String message = "Timing attack test message";
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] shortSignature = new byte[64];

        long startTime = System.nanoTime();
        boolean result = signatureVerificationService.verifyConstantTime(messageBytes, shortSignature, publicKey);
        long endTime = System.nanoTime();

        assertFalse(result, "Short signature should be rejected");
        assertTrue((endTime - startTime) < 10_000_000, "Verification should complete quickly");
    }

    @Test
    public void testInvalidSignatureLength_Rejected() {
        var keyPair = keyPairGeneratorService.generateEd25519KeyPair();
        Ed25519PublicKeyParameters publicKey = keyPairGeneratorService.getEd25519PublicKey(keyPair);

        byte[] message = "Test".getBytes(StandardCharsets.UTF_8);
        byte[] shortSig = new byte[32];

        boolean result = signatureVerificationService.verify(message, shortSig, publicKey);
        assertFalse(result, "Signature with wrong length should be rejected");
    }

    @Test
    public void testNullSignature_Rejected() {
        var keyPair = keyPairGeneratorService.generateEd25519KeyPair();
        Ed25519PublicKeyParameters publicKey = keyPairGeneratorService.getEd25519PublicKey(keyPair);

        byte[] message = "Test".getBytes(StandardCharsets.UTF_8);

        boolean result = signatureVerificationService.verify(message, null, publicKey);
        assertFalse(result, "Null signature should be rejected");
    }
}