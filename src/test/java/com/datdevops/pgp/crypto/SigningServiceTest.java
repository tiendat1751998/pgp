package com.datdevops.pgp.crypto;

import com.datdevops.pgp.service.KeyPairGeneratorService;
import com.datdevops.pgp.service.SigningService;
import com.datdevops.pgp.service.SignatureVerificationService;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SigningServiceTest {

    private final KeyPairGeneratorService keyPairGenerator = new KeyPairGeneratorService();
    private final SigningService signingService = new SigningService();
    private final SignatureVerificationService verificationService = new SignatureVerificationService();

    @Test
    void shouldSignAndVerifyMessage() {
        // Given
        var keyPair = keyPairGenerator.generateEd25519KeyPair();
        byte[] message = "Test message for signing".getBytes();
        Ed25519PrivateKeyParameters privateKey = keyPairGenerator.getEd25519PrivateKey(keyPair);
        Ed25519PublicKeyParameters publicKey = keyPairGenerator.getEd25519PublicKey(keyPair);

        // When
        byte[] signature = signingService.sign(message, privateKey);
        boolean isValid = verificationService.verify(message, signature, publicKey);

        // Then
        assertNotNull(signature);
        assertEquals(64, signature.length); // Ed25519 signature size
        assertTrue(isValid);
    }

    @Test
    void shouldRejectInvalidSignature() {
        // Given
        var keyPair1 = keyPairGenerator.generateEd25519KeyPair();
        var keyPair2 = keyPairGenerator.generateEd25519KeyPair(); // Different key pair
        byte[] message = "Test message".getBytes();
        Ed25519PrivateKeyParameters privateKey1 = keyPairGenerator.getEd25519PrivateKey(keyPair1);
        Ed25519PublicKeyParameters publicKey2 = keyPairGenerator.getEd25519PublicKey(keyPair2);

        // When
        byte[] signature = signingService.sign(message, privateKey1);
        boolean isValid = verificationService.verify(message, signature, publicKey2);

        // Then
        assertNotNull(signature);
        assertFalse(isValid); // Should fail because keys don't match
    }

    @Test
    void shouldRejectTamperedMessage() {
        // Given
        var keyPair = keyPairGenerator.generateEd25519KeyPair();
        byte[] originalMessage = "Original message".getBytes();
        byte[] tamperedMessage = "Tampered message".getBytes();
        Ed25519PrivateKeyParameters privateKey = keyPairGenerator.getEd25519PrivateKey(keyPair);
        Ed25519PublicKeyParameters publicKey = keyPairGenerator.getEd25519PublicKey(keyPair);

        // When
        byte[] signature = signingService.sign(originalMessage, privateKey);
        boolean isValid = verificationService.verify(tamperedMessage, signature, publicKey);

        // Then
        assertNotNull(signature);
        assertFalse(isValid); // Should fail because message was tampered
    }
}
