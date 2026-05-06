package com.datdevops.pgp.service;

import org.springframework.stereotype.Component;

/**
 * RSA key generation strategy implementation.
 */
@Component
public class RSAKeyGeneratorStrategy implements KeyGeneratorStrategy {

    private final RSAKeyPairGeneratorService rsaKeyPairGeneratorService;

    public RSAKeyGeneratorStrategy(RSAKeyPairGeneratorService rsaKeyPairGeneratorService) {
        this.rsaKeyPairGeneratorService = rsaKeyPairGeneratorService;
    }

    @Override
    public String getKeyType() {
        return "RSA";
    }

    @Override
    public KeyMaterial generate() {
        try {
            var keyPair = rsaKeyPairGeneratorService.generateRSAKeyPair();
            String publicKey = rsaKeyPairGeneratorService.getBase64PublicKey(keyPair);
            String privateKey = rsaKeyPairGeneratorService.getBase64PrivateKey(keyPair);
            return KeyMaterial.create(publicKey, privateKey);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate RSA key", e);
        }
    }

    @Override
    public String getPublicKey(KeyMaterial keyMaterial) {
        return keyMaterial.publicKey();
    }

    @Override
    public String getPrivateKey(KeyMaterial keyMaterial) {
        return keyMaterial.privateKey();
    }
}