package com.datdevops.pgp.service;

import com.datdevops.pgp.security.SenderContext;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.io.DataInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

@Service
public class StreamingCryptoService {
    private static final Logger log = LoggerFactory.getLogger(StreamingCryptoService.class);

    private final EncryptionService encryptionService;
    private final KeyService keyService;
    private final AuditService auditService;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private static final int MAX_SESSION_KEY_LEN = 4096;
    private static final int REQUIRED_SIGNATURE_LEN = 64;
    private static final int KEY_VERSION_LEN = 4;
    private static final int TIMESTAMP_LEN = 8;
    private static final int MAX_SENDER_ID_LEN = 64;
    private static final long STREAM_MESSAGE_TTL_MS = TimeUnit.MINUTES.toMillis(5);

    private final Cache<String, Boolean> streamNonceCache = Caffeine.newBuilder()
            .maximumSize(10000)
            .expireAfterWrite(STREAM_MESSAGE_TTL_MS, TimeUnit.MILLISECONDS)
            .build();

    public StreamingCryptoService(EncryptionService encryptionService,
            KeyService keyService,
            AuditService auditService) {
        this.encryptionService = encryptionService;
        this.keyService = keyService;
        this.auditService = auditService;
    }

    /**
     * HARDENED Binary Protocol (senderId + MANDATORY SIGNATURE + KEY VERSION):
     * [4 bytes senderIdLen][senderId][4 bytes sigLen = 64][64 bytes Ed25519 signature][4 bytes keyVersion][8 bytes timestamp][4 bytes sessionKeyLen][encryptedSessionKey][12 bytes nonce][encrypted payload]
     * Signature covers (Length-Value encoded): senderId, sessionKey, nonce, recipientId, keyVersion, timestamp
     */
    public void encryptStream(InputStream input, OutputStream output, String recipientId) throws Exception {
        String senderId = SenderContext.getSenderId();
        if (senderId == null)
            throw new SecurityException("Unauthorized");

        if (senderId.length() > MAX_SENDER_ID_LEN) {
            throw new SecurityException("Sender ID exceeds maximum length");
        }

        log.info("[STREAMING] Starting encryption for recipient: {}", recipientId);

        RSAKeyParameters recipientPubKey = keyService.getRecipientPublicKey(recipientId);

        byte[] sessionKey = new byte[32];
        SECURE_RANDOM.nextBytes(sessionKey);
        byte[] nonce = new byte[12];
        SECURE_RANDOM.nextBytes(nonce);

        long timestamp = System.currentTimeMillis();
        int keyVersion = getCurrentKeyVersion(senderId, "RSA");

        byte[] encryptedSessionKey = encryptionService.encryptSessionKey(sessionKey, recipientPubKey);

        Ed25519PrivateKeyParameters senderEd25519Key = keyService.getSenderSigningKey(senderId);

        byte[] dataToSign = buildSignaturePayload(senderId, sessionKey, nonce, recipientId, keyVersion, timestamp);

        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, senderEd25519Key);
        signer.update(dataToSign, 0, dataToSign.length);
        byte[] signature = signer.generateSignature();

        byte[] senderIdBytes = senderId.getBytes(StandardCharsets.UTF_8);
        output.write(intToByteArray(senderIdBytes.length));
        output.write(senderIdBytes);

        output.write(intToByteArray(REQUIRED_SIGNATURE_LEN));
        output.write(signature);

        output.write(intToByteArray(keyVersion));
        output.write(longToByteArray(timestamp));

        output.write(intToByteArray(encryptedSessionKey.length));
        output.write(encryptedSessionKey);
        output.write(nonce);

        encryptionService.encryptStream(input, output, sessionKey, nonce, null);

        auditService.logEncrypt("STREAM-" + System.currentTimeMillis(), senderId, recipientId, "BINARY_STREAM", true);
        log.info("[STREAMING] Encryption completed for recipient: {}", recipientId);
    }

    private int getCurrentKeyVersion(String partnerId, String keyType) {
        try {
            var repo = keyService.getKeyVersionRepository();
            if (repo != null) {
                var keyVersion = repo.findActiveKey(partnerId, keyType).orElse(null);
                if (keyVersion != null) {
                    return keyVersion.getVersion();
                }
            }
        } catch (Exception e) {
            log.warn("Could not get key version for {}, using default", partnerId);
        }
        return 1;
    }

    /**
     * HARDENED: Decrypt stream with senderId from protocol + MANDATORY signature verification + key version support + replay protection.
     */
    public void decryptStream(InputStream input, OutputStream output) throws Exception {
        String recipientId = SenderContext.getSenderId();
        if (recipientId == null)
            throw new SecurityException("Unauthorized - no recipient identity");

        log.info("[STREAMING] Starting decryption for recipient: {}", recipientId);

        RSAKeyParameters ourPrivKey = keyService.getOurDecryptionKey(recipientId);

        DataInputStream dataIn = new DataInputStream(input);

        byte[] senderIdLenBuf = new byte[4];
        dataIn.readFully(senderIdLenBuf);
        int senderIdLen = byteArrayToInt(senderIdLenBuf);

        if (senderIdLen <= 0 || senderIdLen > MAX_SENDER_ID_LEN) {
            log.error("[SECURITY_BREACH] Invalid senderId length: {} | recipient={}", senderIdLen, recipientId);
            throw new SecurityException("Invalid sender ID in protocol header");
        }

        byte[] senderIdBytes = new byte[senderIdLen];
        dataIn.readFully(senderIdBytes);
        String senderId = new String(senderIdBytes, StandardCharsets.UTF_8);

        if (!senderId.matches("^[a-zA-Z0-9_-]+$")) {
            log.error("[SECURITY_BREACH] Invalid senderId format: {} | recipient={}", senderId, recipientId);
            throw new SecurityException("Invalid sender ID format");
        }

        byte[] sigLenBuf = new byte[4];
        dataIn.readFully(sigLenBuf);
        int sigLen = byteArrayToInt(sigLenBuf);

        if (sigLen != REQUIRED_SIGNATURE_LEN) {
            log.error("[SECURITY_BREACH] Invalid signature length: {} (expected {})", sigLen, REQUIRED_SIGNATURE_LEN);
            throw new SecurityException("Invalid signature length - signature is mandatory");
        }

        byte[] providedSignature = new byte[REQUIRED_SIGNATURE_LEN];
        dataIn.readFully(providedSignature);

        byte[] keyVersionBuf = new byte[KEY_VERSION_LEN];
        dataIn.readFully(keyVersionBuf);
        int keyVersion = byteArrayToInt(keyVersionBuf);

        byte[] timestampBuf = new byte[TIMESTAMP_LEN];
        dataIn.readFully(timestampBuf);
        long timestamp = byteArrayToLong(timestampBuf);

        long now = System.currentTimeMillis();
        if (Math.abs(now - timestamp) > STREAM_MESSAGE_TTL_MS) {
            throw new SecurityException("Streaming message expired or too far in future");
        }

        byte[] lenBuf = new byte[4];
        dataIn.readFully(lenBuf);
        int sessionKeyLen = byteArrayToInt(lenBuf);

        if (sessionKeyLen <= 0 || sessionKeyLen > MAX_SESSION_KEY_LEN) {
            log.error("[SECURITY_BREACH] Invalid session key length: {} | recipient={}", sessionKeyLen, recipientId);
            throw new IllegalArgumentException("Invalid encrypted payload header");
        }

        byte[] encryptedSessionKey = new byte[sessionKeyLen];
        dataIn.readFully(encryptedSessionKey);

        byte[] nonce = new byte[12];
        dataIn.readFully(nonce);

        // Replay Protection: Use sender + recipient + timestamp + nonce to ensure uniqueness
        String streamNonceKey = senderId + ":" + recipientId + ":" + timestamp + ":" + Base64.getEncoder().encodeToString(nonce);
        if (!validateStreamNonce(streamNonceKey)) {
            throw new SecurityException("Replay attack detected - duplicate stream message");
        }

        byte[] sessionKey = encryptionService.decryptSessionKey(encryptedSessionKey, ourPrivKey);

        Ed25519PublicKeyParameters senderEd25519Key = keyService.getSenderEd25519Key(senderId, keyVersion);

        if (senderEd25519Key == null) {
            log.error("[SECURITY_BREACH] Unknown sender: {} | recipient={}", senderId, recipientId);
            throw new SecurityException("Unknown sender - no trusted Ed25519 key");
        }

        byte[] dataToVerify = buildSignaturePayload(senderId, sessionKey, nonce, recipientId, keyVersion, timestamp);

        Ed25519Signer verifier = new Ed25519Signer();
        verifier.init(false, senderEd25519Key);
        verifier.update(dataToVerify, 0, dataToVerify.length);

        boolean sigValid = verifier.verifySignature(providedSignature);

        if (!sigValid) {
            log.error("[SECURITY_BREACH] Invalid Ed25519 signature from sender: {} | expected sender={}", senderId, senderId);
            throw new SecurityException("Invalid sender signature - message may have been tampered");
        }

        encryptionService.decryptStream(input, output, sessionKey, nonce, null);

        auditService.logDecrypt("STREAM-" + System.currentTimeMillis(), senderId, recipientId, "BINARY_STREAM", true);
        log.info("[STREAMING] Decryption completed for recipient: {}", recipientId);
    }

    private boolean validateStreamNonce(String streamNonceKey) {
        if (streamNonceCache.getIfPresent(streamNonceKey) != null) {
            log.warn("[SECURITY_BREACH] Replay attack detected - duplicate nonce: {}", streamNonceKey);
            return false;
        }
        streamNonceCache.put(streamNonceKey, Boolean.TRUE);
        return true;
    }

    private byte[] buildSignaturePayload(String senderId, byte[] sessionKey, byte[] nonce, String recipientId, int keyVersion, long timestamp) {
        byte[] senderBytes = senderId.getBytes(StandardCharsets.UTF_8);
        byte[] recipientBytes = recipientId.getBytes(StandardCharsets.UTF_8);
        byte[] keyVersionBytes = intToByteArray(keyVersion);
        byte[] timestampBytes = longToByteArray(timestamp);

        // HARDENED: Use Length-Value encoding [len][data] instead of delimiters
        int totalLen = 4 + senderBytes.length +
                       4 + sessionKey.length +
                       4 + nonce.length +
                       4 + recipientBytes.length +
                       4 + keyVersionBytes.length +
                       4 + timestampBytes.length;

        byte[] payload = new byte[totalLen];
        int offset = 0;
        
        offset = writeField(payload, offset, senderBytes);
        offset = writeField(payload, offset, sessionKey);
        offset = writeField(payload, offset, nonce);
        offset = writeField(payload, offset, recipientBytes);
        offset = writeField(payload, offset, keyVersionBytes);
        offset = writeField(payload, offset, timestampBytes);
        
        return payload;
    }

    private int writeField(byte[] buffer, int offset, byte[] data) {
        byte[] len = intToByteArray(data.length);
        System.arraycopy(len, 0, buffer, offset, 4);
        System.arraycopy(data, 0, buffer, offset + 4, data.length);
        return offset + 4 + data.length;
    }

    private int byteArrayToInt(byte[] b) {
        if (b == null || b.length < 4) return 0;
        return b[3] & 0xFF |
                (b[2] & 0xFF) << 8 |
                (b[1] & 0xFF) << 16 |
                (b[0] & 0xFF) << 24;
    }

    private long byteArrayToLong(byte[] b) {
        if (b == null || b.length < 8) return 0L;
        return ((long) b[7] & 0xFF) |
                ((long) b[6] & 0xFF) << 8 |
                ((long) b[5] & 0xFF) << 16 |
                ((long) b[4] & 0xFF) << 24 |
                ((long) b[3] & 0xFF) << 32 |
                ((long) b[2] & 0xFF) << 40 |
                ((long) b[1] & 0xFF) << 48 |
                ((long) b[0] & 0xFF) << 56;
    }

    private byte[] longToByteArray(long value) {
        return new byte[] {
                (byte) (value >> 56),
                (byte) (value >> 48),
                (byte) (value >> 40),
                (byte) (value >> 32),
                (byte) (value >> 24),
                (byte) (value >> 16),
                (byte) (value >> 8),
                (byte) value
        };
    }

    private byte[] intToByteArray(int value) {
        return new byte[] {
                (byte) (value >> 24),
                (byte) (value >> 16),
                (byte) (value >> 8),
                (byte) value
        };
    }
}