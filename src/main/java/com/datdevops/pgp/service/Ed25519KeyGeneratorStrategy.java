package com.datdevops.pgp.service;

import org.springframework.stereotype.Component;

import java.util.Base64;

/**
 * Ed25519 key generation strategy implementation.
 */
@Component
public class Ed25519KeyGeneratorStrategy implements KeyGeneratorStrategy {

    private final KeyPairGeneratorService keyPairGeneratorService;

    public Ed25519KeyGeneratorStrategy(KeyPairGeneratorService keyPairGeneratorService) {
        this.keyPairGeneratorService = keyPairGeneratorService;
    }

    @Override
    public String getKeyType() {
        return "ED25519";
    }

    @Override
    public KeyMaterial generate() {
        var keyPair = keyPairGeneratorService.generateEd25519KeyPair();
        
        byte[] privateKeyBytes = keyPairGeneratorService.getEd25519PrivateKey(keyPair).getEncoded();
        byte[] publicKeyBytes = keyPairGeneratorService.getEd25519PublicKey(keyPair).getEncoded();
        
        String publicKey = Base64.getEncoder().encodeToString(publicKeyBytes);
        String privateKey = Base64.getEncoder().encodeToString(privateKeyBytes);
        
        return KeyMaterial.create(publicKey, privateKey);
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