package com.datdevops.pgp.service;

import com.datdevops.pgp.security.SenderContext;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

/**
 * High-performance streaming crypto service for large payloads.
 * Bypasses JSON envelope overhead to handle GB-sized files.
 */
@Service
public class StreamingCryptoService {
    private static final Logger log = LoggerFactory.getLogger(StreamingCryptoService.class);

    private final EncryptionService encryptionService;
    private final KeyService keyService;
    private final AuditService auditService;
    private final SecureRandom secureRandom = new SecureRandom();

    public StreamingCryptoService(EncryptionService encryptionService, 
                                 KeyService keyService, 
                                 AuditService auditService) {
        this.encryptionService = encryptionService;
        this.keyService = keyService;
        this.auditService = auditService;
    }

    /**
     * Encrypts a stream using a freshly generated session key, which is then 
     * encrypted with the recipient's RSA public key.
     */
    public void encryptStream(InputStream input, OutputStream output, String recipientId) throws Exception {
        String senderId = SenderContext.getSenderId();
        if (senderId == null) throw new SecurityException("Unauthorized");

        log.info("[STREAMING] Starting encryption for recipient: {}", recipientId);

        // 1. Resolve Recipient Key
        RSAKeyParameters recipientPubKey = keyService.getRecipientPublicKey(recipientId);

        // 2. Generate Session Key (256-bit AES)
        byte[] sessionKey = new byte[32];
        secureRandom.nextBytes(sessionKey);
        byte[] nonce = new byte[12];
        secureRandom.nextBytes(nonce);

        // 3. Encrypt Session Key with RSA-OAEP
        byte[] encryptedSessionKey = encryptionService.encryptSessionKey(sessionKey, recipientPubKey);

        // 4. Write Metadata Header (Simple Binary Protocol for Streaming)
        // [4 bytes session key length][encrypted session key][12 bytes nonce]
        output.write(intToByteArray(encryptedSessionKey.length));
        output.write(encryptedSessionKey);
        output.write(nonce);

        // 5. Encrypt Payload
        encryptionService.encryptStream(input, output, sessionKey, nonce, null);

        // 6. Audit
        auditService.logEncrypt("STREAM-" + System.currentTimeMillis(), senderId, recipientId, "BINARY_STREAM", true);
        log.info("[STREAMING] Encryption completed for recipient: {}", recipientId);
    }

    public void decryptStream(InputStream input, OutputStream output) throws Exception {
        String recipientId = SenderContext.getSenderId();
        if (recipientId == null) throw new SecurityException("Unauthorized");

        log.info("[STREAMING] Starting decryption for recipient: {}", recipientId);

        // 1. Resolve Our Private Key
        RSAKeyParameters ourPrivKey = keyService.getOurDecryptionKey(recipientId);

        // 2. Read Metadata Header
        byte[] lenBuf = new byte[4];
        if (input.read(lenBuf) != 4) throw new IllegalArgumentException("Invalid stream header");
        int sessionKeyLen = byteArrayToInt(lenBuf);

        byte[] encryptedSessionKey = new byte[sessionKeyLen];
        if (input.read(encryptedSessionKey) != sessionKeyLen) throw new IllegalArgumentException("Incomplete session key");

        byte[] nonce = new byte[12];
        if (input.read(nonce) != 12) throw new IllegalArgumentException("Incomplete nonce");

        // 3. Decrypt Session Key
        byte[] sessionKey = encryptionService.decryptSessionKey(encryptedSessionKey, ourPrivKey);

        // 4. Decrypt Payload
        encryptionService.decryptStream(input, output, sessionKey, nonce, null);

        // 5. Audit
        auditService.logDecrypt("STREAM-" + System.currentTimeMillis(), "UNKNOWN", recipientId, "BINARY_STREAM", true);
        log.info("[STREAMING] Decryption completed for recipient: {}", recipientId);
    }

    private byte[] intToByteArray(int value) {
        return new byte[] {
            (byte)(value >> 24),
            (byte)(value >> 16),
            (byte)(value >> 8),
            (byte)value
        };
    }

    private int byteArrayToInt(byte[] b) {
        return   b[3] & 0xFF |
                (b[2] & 0xFF) << 8 |
                (b[1] & 0xFF) << 16 |
                (b[0] & 0xFF) << 24;
    }
}
