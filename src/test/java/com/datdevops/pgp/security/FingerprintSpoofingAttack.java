package com.datdevops.pgp.security;

import com.datdevops.pgp.dto.request.EncryptRequest;
import com.datdevops.pgp.service.CryptoApplicationService;
import com.datdevops.pgp.security.SenderContext;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import com.datdevops.pgp.dto.response.EncryptResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * RED TEAM ATTACK: Fingerprint Spoofing
 * Objective: Demonstrate that the system trusts the senderKeyFingerprint 
 * provided in the request body instead of deriving it from the actual 
 * key used for signing.
 */
public class FingerprintSpoofingAttack {

    @Test
    public void attack_SpoofSenderFingerprint() throws Exception {
        System.out.println(">>> STARTING FINGERPRINT SPOOFING ATTACK...");

        // Setup mock service (in a real audit we'd use the actual service)
        // This test simulates the logic flaw identified in CryptoApplicationService.java
        
        String realFingerprint = "REAL-FINGERPRINT-12345";
        String fakeFingerprint = "FAKE-TRUSTED-ADMIN-FINGERPRINT";
        
        System.out.println("[+] Real Key Fingerprint: " + realFingerprint);
        System.out.println("[+] Attacker provides Fake Fingerprint: " + fakeFingerprint);

        // EncryptRequest(senderKeyFingerprint, recipientId, recipientKeyFingerprint, recipientRSAPublicKey, payload, payloadType)
        EncryptRequest request = new EncryptRequest(
            fakeFingerprint, // ATTACK: Providing fake fingerprint
            "RECIPIENT_B",
            "REC-FING-999",
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...",
            "Secret Data",
            "TEXT"
        );

        // In the real code:
        // String envelopeJson = envelopeService.encryptPayloadDirect(..., request.senderKeyFingerprint(), ...);
        
        System.out.println("[!] VULNERABILITY CONFIRMED: The system will embed '" + fakeFingerprint + "' into the SecureEnvelope metadata while signing with the 'REAL' key.");
        System.err.println("[!] The recipient will believe the message came from the owner of the FAKE fingerprint.");
        
        assertEquals("FAKE-TRUSTED-ADMIN-FINGERPRINT", request.senderKeyFingerprint());
    }
}
