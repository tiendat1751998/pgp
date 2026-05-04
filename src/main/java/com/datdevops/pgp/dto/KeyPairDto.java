package com.datdevops.pgp.dto;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

/**
 * Data Transfer Object representing a cryptographic key pair.
 * Supports both Ed25519 (signing) and X25519 (key exchange) key types.
 */
public class KeyPairDto {
    private final AsymmetricKeyParameter privateKey;
    private final AsymmetricKeyParameter publicKey;
    private final KeyType keyType;

    public enum KeyType {
        ED25519,
        X25519
    }

    public KeyPairDto(AsymmetricCipherKeyPair keyPair, KeyType keyType) {
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
        this.keyType = keyType;
    }

    public AsymmetricKeyParameter getPrivateKey() {
        return privateKey;
    }

    public AsymmetricKeyParameter getPublicKey() {
        return publicKey;
    }

    public KeyType getKeyType() {
        return keyType;
    }

    // Convenience methods for typed access
    public Ed25519PrivateKeyParameters getEd25519PrivateKey() {
        if (keyType != KeyType.ED25519) {
            throw new IllegalStateException("Key pair is not of type ED25519");
        }
        return (Ed25519PrivateKeyParameters) privateKey;
    }

    public Ed25519PublicKeyParameters getEd25519PublicKey() {
        if (keyType != KeyType.ED25519) {
            throw new IllegalStateException("Key pair is not of type ED25519");
        }
        return (Ed25519PublicKeyParameters) publicKey;
    }

    public X25519PrivateKeyParameters getX25519PrivateKey() {
        if (keyType != KeyType.X25519) {
            throw new IllegalStateException("Key pair is not of type X25519");
        }
        return (X25519PrivateKeyParameters) privateKey;
    }

    public X25519PublicKeyParameters getX25519PublicKey() {
        if (keyType != KeyType.X25519) {
            throw new IllegalStateException("Key pair is not of type X25519");
        }
        return (X25519PublicKeyParameters) publicKey;
    }
}
