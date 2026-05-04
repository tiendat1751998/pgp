package com.datdevops.pgp.listener;

import com.datdevops.pgp.util.DatabaseColumnEncryptor;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.PostLoad;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Base64;

public class EntityEncryptionListener {

    private static final String ENCRYPTED_PREFIX = "ENC:";

    private static DatabaseColumnEncryptor encryptor;
    private static String masterKey;

    public static void initialize(String key) {
        if (masterKey == null || !masterKey.equals(key)) {
            masterKey = key;
            encryptor = new DatabaseColumnEncryptor(key);
        }
    }

    @PrePersist
    public void encryptFields(Object entity) {
        processEncryptedFields(entity, true);
    }

    @PreUpdate
    public void encryptFieldsOnUpdate(Object entity) {
        processEncryptedFields(entity, true);
    }

    @PostLoad
    public void decryptFields(Object entity) {
        processEncryptedFields(entity, false);
    }

    private void processEncryptedFields(Object entity, boolean encrypt) {
        if (encryptor == null) return;

        Arrays.stream(entity.getClass().getDeclaredFields())
            .filter(f -> f.isAnnotationPresent(Encrypted.class))
            .forEach(field -> {
                try {
                    field.setAccessible(true);
                    Object value = field.get(entity);

                    if (encrypt && value != null && !isEncrypted((String) value)) {
                        String encrypted = encryptor.encrypt((String) value);
                        field.set(entity, ENCRYPTED_PREFIX + encrypted);
                    } else if (!encrypt && value != null && isEncrypted((String) value)) {
                        String encryptedValue = ((String) value).substring(ENCRYPTED_PREFIX.length());
                        String decrypted = encryptor.decrypt(encryptedValue);
                        field.set(entity, decrypted);
                    }
                } catch (Exception e) {
                    throw new RuntimeException("Failed to process encrypted field: " + field.getName(), e);
                }
            });
    }

    private boolean isEncrypted(String value) {
        if (value == null || value.isEmpty()) return false;
        return value.startsWith(ENCRYPTED_PREFIX);
    }
}