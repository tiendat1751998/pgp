package com.datdevops.pgp.service;

import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.springframework.stereotype.Service;

/**
 * Service for creating digital signatures using Ed25519.
 */
@Service
public class SigningService {

    /**
     * Signs a message using the provided private key.
     *
     * @param message the message to sign (as bytes)
     * @param privateKey the Ed25519 private key
     * @return the signature bytes
     */
    public byte[] sign(byte[] message, Ed25519PrivateKeyParameters privateKey) {
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, privateKey); // true for signing
        signer.update(message, 0, message.length);
        return signer.generateSignature();
    }
}
