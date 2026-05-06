package com.datdevops.pgp.security;

import com.datdevops.pgp.service.KeyStorageService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
public class DefaultCredentialsTest {

    @Autowired
    private KeyStorageService keyStorageService;

    @Test
    public void testKeystorePassword_NotUsingDefaultChangeit() throws Exception {
        Object passwordObj = ReflectionTestUtils.getField(keyStorageService, "keystorePassword");
        String password = passwordObj != null ? passwordObj.toString() : null;

        assertNotNull(password, "Keystore password should be configured");
        assertFalse("changeit".equals(password),
            "Keystore password must NOT be the default 'changeit' - this is a well-known vulnerability");
    }

    @Test
    public void testKeystorePassword_IsConfigured() throws Exception {
        Object passwordObj = ReflectionTestUtils.getField(keyStorageService, "keystorePassword");
        String password = passwordObj != null ? passwordObj.toString() : null;

        assertTrue(password != null && !password.isEmpty(),
            "Keystore password should be set (via environment variable KEYSTORE_PASSWORD)");
    }

    @Test
    public void testVaultPath_IsValid() throws Exception {
        Object vaultPathObj = ReflectionTestUtils.getField(keyStorageService, "vaultPath");
        String vaultPath = vaultPathObj != null ? vaultPathObj.toString() : null;

        assertNotNull(vaultPath, "Vault path should be configured");
        assertFalse(vaultPath.isEmpty(), "Vault path should not be empty");
    }
}