package com.datdevops.pgp.crypto;

import com.datdevops.pgp.service.KeyPairGeneratorService;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class KeyPairGeneratorServiceTest {

    private final KeyPairGeneratorService keyPairGenerator = new KeyPairGeneratorService();

    @Test
    void shouldGenerateEd25519KeyPair() {
        // When
        var keyPair = keyPairGenerator.generateEd25519KeyPair();

        // Then
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
        assertTrue(keyPair.getPrivate() instanceof Ed25519PrivateKeyParameters);
        assertTrue(keyPair.getPublic() instanceof Ed25519PublicKeyParameters);
    }

    @Test
    void shouldGenerateX25519KeyPair() {
        // When
        var keyPair = keyPairGenerator.generateX25519KeyPair();

        // Then
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
        assertTrue(keyPair.getPrivate() instanceof X25519PrivateKeyParameters);
        assertTrue(keyPair.getPublic() instanceof X25519PublicKeyParameters);
    }

    @Test
    void shouldExtractPrivateAndPublicKey() {
        // Given
        var keyPair = keyPairGenerator.generateEd25519KeyPair();

        // When
        var privateKey = keyPairGenerator.getPrivateKey(keyPair);
        var publicKey = keyPairGenerator.getPublicKey(keyPair);

        // Then
        assertNotNull(privateKey);
        assertNotNull(publicKey);
        assertSame(keyPair.getPrivate(), privateKey);
        assertSame(keyPair.getPublic(), publicKey);
    }
}
