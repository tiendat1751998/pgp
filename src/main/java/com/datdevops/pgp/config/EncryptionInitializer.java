package com.datdevops.pgp.config;

import com.datdevops.pgp.listener.EntityEncryptionListener;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Profile("!test")
public class EncryptionInitializer implements CommandLineRunner {

    @Value("${app.db.encryption.master-key:}")
    private String masterKey;

    @Value("${app.db.encryption.enabled:false}")
    private boolean encryptionEnabled;

    @Override
    public void run(String... args) {
        if (encryptionEnabled && masterKey != null && !masterKey.isEmpty()) {
            EntityEncryptionListener.initialize(masterKey);
        }
    }
}