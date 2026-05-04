package com.datdevops.pgp.service;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.springframework.stereotype.Service;
import java.security.SecureRandom;

/**
 * Service for generating cryptographic key pairs.
 * Supports Ed25519 for signatures and X25519 for key exchange.
 */
@Service
public class KeyPairGeneratorService {

    private final SecureRandom secureRandom;

    public KeyPairGeneratorService() {
        this.secureRandom = new SecureRandom();
    }

    /**
     * Generates an Ed25519 key pair for digital signatures.
     *
     * @return a key pair containing the private and public key parameters
     */
    public AsymmetricCipherKeyPair generateEd25519KeyPair() {
        Ed25519KeyPairGenerator generator = new Ed25519KeyPairGenerator();
        generator.init(new Ed25519KeyGenerationParameters(secureRandom));
        return generator.generateKeyPair();
    }

    /**
     * Generates an X25519 key pair for key exchange (used in encryption).
     *
     * @return a key pair containing the private and public key parameters
     */
    public AsymmetricCipherKeyPair generateX25519KeyPair() {
        X25519KeyPairGenerator generator = new X25519KeyPairGenerator();
        generator.init(new X25519KeyGenerationParameters(secureRandom));
        return generator.generateKeyPair();
    }

    /**
     * Extracts the private key from an asymmetric key pair.
     *
     * @param keyPair the asymmetric key pair
     * @return the private key parameter
     */
    public AsymmetricKeyParameter getPrivateKey(AsymmetricCipherKeyPair keyPair) {
        return keyPair.getPrivate();
    }

    /**
     * Extracts the public key from an asymmetric key pair.
     *
     * @param keyPair the asymmetric key pair
     * @return the public key parameter
     */
    public AsymmetricKeyParameter getPublicKey(AsymmetricCipherKeyPair keyPair) {
        return keyPair.getPublic();
    }

    public Ed25519PrivateKeyParameters getEd25519PrivateKey(AsymmetricCipherKeyPair keyPair) {
        return (Ed25519PrivateKeyParameters) keyPair.getPrivate();
    }

    public Ed25519PublicKeyParameters getEd25519PublicKey(AsymmetricCipherKeyPair keyPair) {
        return (Ed25519PublicKeyParameters) keyPair.getPublic();
    }

    public X25519PrivateKeyParameters getX25519PrivateKey(AsymmetricCipherKeyPair keyPair) {
        return (X25519PrivateKeyParameters) keyPair.getPrivate();
    }

    public X25519PublicKeyParameters getX25519PublicKey(AsymmetricCipherKeyPair keyPair) {
        return (X25519PublicKeyParameters) keyPair.getPublic();
    }
}
