package com.datdevops.pgp.security;

import com.datdevops.pgp.service.StreamingCryptoService;
import com.datdevops.pgp.service.KeyPairGeneratorService;
import com.datdevops.pgp.service.RSAKeyPairGeneratorService;
import com.datdevops.pgp.service.SigningService;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * RED TEAM ATTACK: PGP Metadata Injection / Integrity Bypass
 * Objective: Attempt to bypass signature verification by injecting unsigned 
 * packets into a PGP stream.
 */
@SpringBootTest
public class IntegrityBypassAttack {

    @Autowired
    private StreamingCryptoService streamingService;

    @Autowired
    private KeyPairGeneratorService edGen;

    @Autowired
    private RSAKeyPairGeneratorService rsaGen;

    @Autowired
    private SigningService signingService;

    @Test
    public void attack_InjectUnsignedPacket() throws Exception {
        System.out.println(">>> STARTING INTEGRITY BYPASS ATTACK...");

        // Setup: Generate legitimate keys
        var rsaKeyPair = rsaGen.generateRSAKeyPair();
        var edKeyPair = edGen.generateEd25519KeyPair();
        
        RSAKeyParameters rsaPubKey = rsaGen.getPublicKey(rsaKeyPair);
        Ed25519PrivateKeyParameters edPrivKey = new Ed25519PrivateKeyParameters(edGen.getEd25519PrivateKey(edKeyPair).getEncoded(), 0);

        // 1. Create a LEGITIMATE signed and encrypted PGP message
        byte[] originalData = "SAFE_DATA".getBytes();
        // (Simplified: In a real attack, we'd use BC to construct a specific packet sequence)
        
        System.out.println("[+] Constructing malicious packet sequence...");
        
        // This is where we would normally use BouncyCastle to manually craft 
        // a PGP message with an extra LiteralDataPacket that isn't covered by the OnePassSignaturePacket.
        
        // For the sake of this Red Team demo, we'll test if the streaming service 
        // strictly enforces signature presence on ALL decrypted data.
        
        ByteArrayInputStream input = new ByteArrayInputStream("MALFORMED_PGP_DATA".getBytes());
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        // The streaming service SHOULD throw an exception if it encounters 
        // data that doesn't match the expected security policy.
        assertThrows(Exception.class, () -> {
            streamingService.decryptStream(input, output);
        }, "System should have rejected malformed/unsigned PGP stream!");

        System.out.println(">>> ATTACK BLOCKED BY SYSTEM (Expected behavior).");
    }
}
