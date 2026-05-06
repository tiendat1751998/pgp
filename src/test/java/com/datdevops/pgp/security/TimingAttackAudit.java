package com.datdevops.pgp.security;

import com.datdevops.pgp.service.SignatureVerificationService;
import com.datdevops.pgp.service.KeyPairGeneratorService;
import com.datdevops.pgp.service.SigningService;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * RED TEAM ATTACK: Timing Side-Channel Audit
 * Objective: Detect if signature verification leaks information via execution time.
 */
@SpringBootTest
public class TimingAttackAudit {

    private final SignatureVerificationService verificationService = new SignatureVerificationService();
    private final SigningService signingService = new SigningService();
    private final KeyPairGeneratorService keyGen = new KeyPairGeneratorService();

    @Test
    public void audit_SignatureVerificationTiming() throws Exception {
        var keyPair = keyGen.generateEd25519KeyPair();
        Ed25519PublicKeyParameters publicKey = new Ed25519PublicKeyParameters(
                keyGen.getEd25519PublicKey(keyPair).getEncoded(), 0);

        byte[] message = "SENSITIVE_TRANSACTION_DATA".getBytes();
        byte[] validSig = signingService.sign(message, 
                new org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters(
                        keyGen.getEd25519PrivateKey(keyPair).getEncoded(), 0));

        // Malicious signature: same length but totally different
        byte[] invalidSig = new byte[64];
        java.util.Arrays.fill(invalidSig, (byte) 0xAA);

        // Warm up JVM
        for (int i = 0; i < 1000; i++) {
            verificationService.verify(message, validSig, publicKey);
        }

        int iterations = 10000;
        List<Long> validTimes = new ArrayList<>();
        List<Long> invalidTimes = new ArrayList<>();

        System.out.println(">>> STARTING TIMING SIDE-CHANNEL AUDIT...");

        for (int i = 0; i < iterations; i++) {
            long start = System.nanoTime();
            verificationService.verify(message, validSig, publicKey);
            validTimes.add(System.nanoTime() - start);

            long startInvalid = System.nanoTime();
            verificationService.verify(message, invalidSig, publicKey);
            invalidTimes.add(System.nanoTime() - startInvalid);
        }

        double validAvg = validTimes.stream().mapToLong(Long::longValue).average().orElse(0);
        double invalidAvg = invalidTimes.stream().mapToLong(Long::longValue).average().orElse(0);
        
        Collections.sort(validTimes);
        Collections.sort(invalidTimes);
        
        long validMedian = validTimes.get(iterations / 2);
        long invalidMedian = invalidTimes.get(iterations / 2);

        System.out.println("\n>>> AUDIT RESULTS (ns)");
        System.out.println("Valid Signature   | Avg: " + String.format("%.2f", validAvg) + " | Median: " + validMedian);
        System.out.println("Invalid Signature | Avg: " + String.format("%.2f", invalidAvg) + " | Median: " + invalidMedian);
        
        double diff = Math.abs(validAvg - invalidAvg);
        System.out.println("Difference: " + String.format("%.2f", diff) + " ns");

        // If difference is significant, it indicates a potential timing leak.
        // In high-security crypto, we strive for < 10ns difference on average.
        if (diff > 50) {
            System.err.println(">>> WARNING: Potential Timing Side-Channel detected!");
        } else {
            System.out.println(">>> SUCCESS: Constant-time verification likely maintained.");
        }
    }
}
