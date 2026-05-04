package com.datdevops.pgp.service;

import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.springframework.stereotype.Service;

/**
 * Service for verifying digital signatures using Ed25519.
 */
@Service
public class SignatureVerificationService {

    /**
     * Verifies a signature for the given message using the public key.
     *
     * @param message the original message (as bytes)
     * @param signature the signature bytes to verify
     * @param publicKey the Ed25519 public key
     * @return true if the signature is valid, false otherwise
     */
    public boolean verify(byte[] message, byte[] signature, Ed25519PublicKeyParameters publicKey) {
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(false, publicKey); // false for verification
        signer.update(message, 0, message.length);
        return signer.verifySignature(signature);
    }
}
