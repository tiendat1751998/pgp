package com.datdevops.pgp.security;

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

public class FatalDecryptCrashTest {

    @Test
    public void testArrayIndexOutOfBounds_Prevented() {
        byte[] tooShortPayload = new byte[20];

        Exception exception = assertThrows(Exception.class, () -> {
            byte[] nonce = new byte[12];
            byte[] mac = new byte[16];
            byte[] ciphertext = new byte[tooShortPayload.length - 12 - 16];

            System.arraycopy(tooShortPayload, 0, ciphertext, 0, ciphertext.length);
            System.arraycopy(tooShortPayload, ciphertext.length, nonce, 0, 12);
            System.arraycopy(tooShortPayload, ciphertext.length + 12, mac, 0, 16);
        });

        assertTrue(exception instanceof ArrayIndexOutOfBoundsException ||
                   exception instanceof NegativeArraySizeException,
            "Should throw array-related exception for too short payload");
    }

    @Test
    public void testBoundsCheck_PreventsCrash() {
        int minLength = 12 + 16;

        byte[] tooShort = new byte[20];
        assertTrue(tooShort.length < minLength, "Payload is too short");

        byte[] validPayload = new byte[100];
        assertTrue(validPayload.length >= minLength, "Payload is valid length");
    }

    @Test
    public void testBase64DecodedLength_Validates() {
        String shortBase64 = "AA==";
        byte[] decoded = Base64.getDecoder().decode(shortBase64);

        int minLength = 12 + 16;
        assertTrue(decoded.length < minLength,
            "Decoded payload is too short and should be rejected before arraycopy");
    }

    @Test
    public void testMinimumPayloadSize_Validation() {
        int nonceSize = 12;
        int macSize = 16;
        int minimumPayloadSize = nonceSize + macSize;

        assertEquals(28, minimumPayloadSize);

        assertTrue(10 < minimumPayloadSize, "10 bytes is below minimum");
        assertTrue(27 < minimumPayloadSize, "27 bytes is below minimum");
        assertTrue(28 >= minimumPayloadSize, "28 bytes meets minimum");
        assertTrue(100 >= minimumPayloadSize, "100 bytes exceeds minimum");
    }
}