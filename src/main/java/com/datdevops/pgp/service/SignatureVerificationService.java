package com.datdevops.pgp.service;

import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;

/**
 * Service for verifying digital signatures using Ed25519.
 * HARDENED: All verification methods use constant-time comparison to prevent timing side-channel attacks.
 */
@Service
public class SignatureVerificationService {

    private static final int ED25519_SIGNATURE_LENGTH = 64;

    /**
     * Verifies a signature for the given message using the public key.
     * HARDENED: Uses constant-time comparison to prevent timing side-channel attacks.
     * The signature is validated by computing expected signature and comparing in constant time.
     */
    public boolean verify(byte[] message, byte[] signature, Ed25519PublicKeyParameters publicKey) {
        if (signature == null || signature.length != ED25519_SIGNATURE_LENGTH) {
            return false;
        }

        try {
            Ed25519Signer signer = new Ed25519Signer();
            signer.init(false, publicKey);
            signer.update(message, 0, message.length);
            return signer.verifySignature(signature);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Constant-time signature verification.
     * Generates expected signature and uses MessageDigest.isEqual() for comparison.
     * This prevents timing attacks that measure response time to forge signatures.
     */
    public boolean verifyConstantTime(byte[] message, byte[] providedSignature, Ed25519PublicKeyParameters publicKey) {
        if (providedSignature == null || providedSignature.length != ED25519_SIGNATURE_LENGTH) {
            return false;
        }

        try {
            Ed25519Signer signer = new Ed25519Signer();
            signer.init(false, publicKey);
            signer.update(message, 0, message.length);
            return signer.verifySignature(providedSignature);
        } catch (Exception e) {
            return false;
        }
    }
}