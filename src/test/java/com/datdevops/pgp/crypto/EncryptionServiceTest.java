package com.datdevops.pgp.crypto;

import com.datdevops.pgp.service.EncryptionService;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class EncryptionServiceTest {

    private final EncryptionService encryptionService = new EncryptionService();

    @Test
    void shouldEncryptAndDecryptData() {
        // Given
        byte[] key = new byte[32]; // AES-256 key
        byte[] plaintext = "Hello, World! This is a test message.".getBytes();
        byte[] associatedData = "associated-data".getBytes();

        // When
        EncryptionService.EncryptionResult result = encryptionService.encrypt(plaintext, key, associatedData);
        byte[] decrypted = encryptionService.decrypt(
                result.getCiphertext(),
                key,
                result.getNonce(),
                result.getMac(),
                associatedData
        );

        // Then
        assertNotNull(result.getCiphertext());
        assertNotNull(result.getNonce());
        assertNotNull(result.getMac());
        assertEquals(12, result.getNonce().length); // GCM nonce size
        assertEquals(16, result.getMac().length);   // AES-GCM MAC size
        assertTrue(Arrays.equals(plaintext, decrypted));
    }

    @Test
    void shouldFailDecryptionWithWrongKey() {
        // Given
        byte[] key1 = new byte[32];
        byte[] key2 = new byte[32];
        key2[0] = 1; // Different key
        byte[] plaintext = "test".getBytes();

        // When
        EncryptionService.EncryptionResult result = encryptionService.encrypt(plaintext, key1, null);

        // Then
        assertThrows(IllegalStateException.class, () -> {
            encryptionService.decrypt(result.getCiphertext(), key2, result.getNonce(), result.getMac(), null);
        });
    }

    @Test
    void shouldHandleEmptyAssociatedData() {
        // Given
        byte[] key = new byte[32];
        byte[] plaintext = "test".getBytes();

        // When
        EncryptionService.EncryptionResult result = encryptionService.encrypt(plaintext, key, null);
        byte[] decrypted = encryptionService.decrypt(
                result.getCiphertext(),
                key,
                result.getNonce(),
                result.getMac(),
                null
        );

        // Then
        assertTrue(Arrays.equals(plaintext, decrypted));
    }
}
