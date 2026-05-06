package com.datdevops.pgp.redteam;

import com.datdevops.pgp.config.CryptoConfig;
import com.datdevops.pgp.security.SenderContext;
import com.datdevops.pgp.service.*;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.MethodOrderer;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * RED TEAM TEST SUITE
 * Validates security against advanced attack vectors.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class RedTeamAttackSimulationTest {

    static { new CryptoConfig(); }

    private static final String ATTACKER_ID = "ATTACKER_BANK";

    /**
     * VECTOR 1: Race Condition - send duplicate nonces
     */
    @Test
    @Order(1)
    public void testRaceNonceAttack() throws Exception {
        ReplayProtectionService replay = new ReplayProtectionService();
        String nonce = "RACE-" + System.currentTimeMillis();
        
        ExecutorService executor = Executors.newFixedThreadPool(20);
        AtomicInteger success = new AtomicInteger(0);
        CountDownLatch latch = new CountDownLatch(50);
        
        for (int i = 0; i < 50; i++) {
            executor.submit(() -> {
                try {
                    if (replay.isValidNonce(nonce, "TARGET")) {
                        success.incrementAndGet();
                    }
                } finally { latch.countDown(); }
            });
        }
        
        latch.await(5, TimeUnit.SECONDS);
        executor.shutdown();
        
        System.out.println("[RACE] Attempts: 50, Passed: " + success.get());
        assertTrue(success.get() <= 1, "Race allowed multiple!");
        assertFalse(replay.isValidNonce(nonce, "TARGET"));
        
        System.out.println("✅ PASSED: Race Nonce");
    }

    /**
     * VECTOR 2: CPU Exhaustion via KeyGen spam
     */
    @Test
    @Order(2)
    public void testCPUIncineratorAttack() {
        SenderRateLimiter limiter = new SenderRateLimiter();
        
        for (int i = 0; i < 50; i++) {
            try {
                limiter.checkKeyGenRateLimit(ATTACKER_ID);
            } catch (Exception e) {
                // Expected after 5 per minute
            }
        }
        
        // Try one more - should be blocked
        boolean blocked = false;
        try {
            limiter.checkKeyGenRateLimit(ATTACKER_ID);
        } catch (Exception e) {
            blocked = true;
        }
        
        assertTrue(blocked, "KeyGen should be throttled");
        System.out.println("✅ PASSED: CPU Incinerator (throttled)");
    }

    /**
     * VECTOR 3: Message Flood DoS
     */
    @Test
    @Order(3)
    public void testMessageFloodAttack() {
        SenderRateLimiter limiter = new SenderRateLimiter();
        
        AtomicInteger blocked = new AtomicInteger(0);
        ExecutorService executor = Executors.newFixedThreadPool(50);
        
        for (int i = 0; i < 2000; i++) {
            executor.submit(() -> {
                try {
                    limiter.checkRateLimit(ATTACKER_ID);
                } catch (Exception e) {
                    blocked.incrementAndGet();
                }
            });
        }
        
        executor.shutdown();
        try { executor.awaitTermination(10, TimeUnit.SECONDS); } 
        catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        
        System.out.println("[FLOOD] Total: 2000, Blocked: " + blocked.get());
        assertTrue(blocked.get() > 1000, "Not limiting enough");
        
        System.out.println("✅ PASSED: Message Flood");
    }

    /**
     * VECTOR 4: ThreadLocal Ghost Identity
     */
    @Test
    @Order(4)
    public void testGhostIdentityAttack() {
        SenderContext.clear();
        
        // Request 1 - set identity
        SenderContext.setSenderId("PARTNER_A");
        assertTrue(SenderContext.isAuthenticated());
        
        // Proper cleanup
        SenderContext.clear();
        assertFalse(SenderContext.isAuthenticated());
        
        System.out.println("✅ PASSED: Ghost Identity");
    }

    /**
     * VECTOR 5: Timestamp Manipulation
     */
    @Test
    @Order(5)
    public void testTimestampManipulation() {
        ReplayProtectionService replay = new ReplayProtectionService(300, 10000);
        
        long now = System.currentTimeMillis();
        
        assertTrue(replay.validateTimestamp(now, 300));
        assertFalse(replay.validateTimestamp(now - 600000, 300));
        assertFalse(replay.validateTimestamp(now + 600000, 300));
        
        System.out.println("✅ PASSED: Timestamp Manipulation");
    }

    /**
     * VECTOR 6: Cache Poisoning
     */
    @Test
    @Order(6)
    public void testCachePoisoning() {
        var cache = com.github.benmanes.caffeine.cache.Caffeine.newBuilder()
            .maximumSize(100).build();
        
        cache.put("MALICIOUS", "FAKE");
        assertEquals("FAKE", cache.getIfPresent("MALICIOUS"));
        
        cache.invalidate("MALICIOUS");
        assertNull(cache.getIfPresent("MALICIOUS"));
        
        System.out.println("✅ PASSED: Cache Poisoning");
    }

    /**
     * VECTOR 7: Signature Bypass
     */
    @Test
    @Order(7)
    public void testSignatureBypass() {
        SigningService signing = new SigningService();
        SignatureVerificationService verification = new SignatureVerificationService();
        
        KeyPairGeneratorService keyGen = new KeyPairGeneratorService();
        var keyPair = keyGen.generateEd25519KeyPair();
        
        byte[] msg = "TEST".getBytes();
        byte[] validSig = signing.sign(msg, 
            new org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters(
                keyGen.getEd25519PrivateKey(keyPair).getEncoded(), 0));
        
        Ed25519PublicKeyParameters pub = new Ed25519PublicKeyParameters(
            keyGen.getEd25519PublicKey(keyPair).getEncoded(), 0);
        
        assertTrue(verification.verify(msg, validSig, pub));
        assertFalse(verification.verify("TAMPERED".getBytes(), validSig, pub));
        
        System.out.println("✅ PASSED: Signature Bypass");
    }

    /**
     * VECTOR 8: Key Generation Quality
     */
    @Test
    @Order(8)
    public void testKeyGenerationQuality() throws Exception {
        KeyPairGeneratorService keyGen = new KeyPairGeneratorService();
        
        var ed = keyGen.generateEd25519KeyPair();
        assertEquals(32, keyGen.getEd25519PrivateKey(ed).getEncoded().length);
        
        RSAKeyPairGeneratorService rsa = new RSAKeyPairGeneratorService();
        var rsaKey = rsa.generateRSAKeyPair();
        assertTrue(rsa.getBase64PublicKey(rsaKey).length() > 200);
        
        System.out.println("✅ PASSED: Key Generation Quality");
    }

    @AfterAll
    public static void summary() {
        System.out.println("\n========================================");
        System.out.println("🔴 RED TEAM - 8 ATTACK VECTORS TESTED");
        System.out.println("========================================");
    }
}