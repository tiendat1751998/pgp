package com.datdevops.pgp.security;

import com.datdevops.pgp.service.StreamingCryptoService;
import com.datdevops.pgp.service.EncryptionService;
import com.datdevops.pgp.service.KeyService;
import com.datdevops.pgp.service.AuditService;
import com.datdevops.pgp.security.SenderContext;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * RED TEAM ATTACK: Streaming Protocol Crash
 * Objective: Demonstrate the ArrayIndexOutOfBoundsException and malformed 
 * protocol state in the StreamingCryptoService.
 */
public class StreamingCrashAttack {

    @Test
    public void attack_StreamingDecryptionCrash() throws Exception {
        System.out.println(">>> STARTING STREAMING CRASH ATTACK...");

        // 1. Setup mocks
        EncryptionService encryptionService = Mockito.mock(EncryptionService.class);
        KeyService keyService = Mockito.mock(KeyService.class);
        AuditService auditService = Mockito.mock(AuditService.class);

        StreamingCryptoService service = new StreamingCryptoService(encryptionService, keyService, auditService);

        // 2. Mock keys
        RSAKeyParameters mockKey = new RSAKeyParameters(true, BigInteger.valueOf(123), BigInteger.valueOf(456));
        when(keyService.getOurDecryptionKey(anyString())).thenReturn(mockKey);
        
        // 3. Set security context
        SenderContext.setSenderId("TARGET_PARTNER");

        // 4. Construct a "valid" header that triggers the bug
        // Header: [sigLen=4][sig=4bytes][keyLen=4][key=4bytes][nonce=12bytes]...
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(new byte[]{0, 0, 0, 4}); // sigLen = 4
        bos.write(new byte[]{1, 2, 3, 4}); // providedSignature
        bos.write(new byte[]{0, 0, 0, 4}); // sessionKeyLen = 4
        bos.write(new byte[]{5, 6, 7, 8}); // encryptedSessionKey
        bos.write(new byte[12]);           // nonce
        
        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // 5. Execute - This SHOULD crash with ArrayIndexOutOfBoundsException
        System.out.println("[+] Triggering decryption with signed stream...");
        
        try {
            service.decryptStream(bis, out);
        } catch (ArrayIndexOutOfBoundsException e) {
            System.err.println("[!] ATTACK SUCCESS: System crashed with " + e.toString());
            System.err.println("[!] Root cause: StreamingCryptoService tries to copy nonce from 32-byte key at index 32.");
            return;
        } catch (Exception e) {
            System.out.println("[?] Caught expected/other exception: " + e.getMessage());
            e.printStackTrace();
        } finally {
            SenderContext.clear();
        }
        
        System.out.println(">>> ATTACK DEMONSTRATION COMPLETE.");
    }
}
