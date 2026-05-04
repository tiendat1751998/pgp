package com.datdevops.pgp.config;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;

/**
 * Configuration class to register Bouncy Castle as a security provider.
 */
public class CryptoConfig {
    public CryptoConfig() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
