package com.datdevops.pgp.listener;

import com.datdevops.pgp.util.DatabaseColumnEncryptor;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.PostLoad;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Listener for transparent entity field encryption.
 * Optimized with field caching and thread-safe initialization.
 */
public class EntityEncryptionListener {

    private static final String ENCRYPTED_PREFIX = "ENC:";
    private static volatile DatabaseColumnEncryptor encryptor;
    
    // Cache annotated fields per class to avoid expensive reflection on every DB operation
    private static final Map<Class<?>, List<Field>> fieldCache = new ConcurrentHashMap<>();

    public static void initialize(String key) {
        if (encryptor == null) {
            synchronized (EntityEncryptionListener.class) {
                if (encryptor == null) {
                    encryptor = new DatabaseColumnEncryptor(key);
                }
            }
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

        Class<?> clazz = entity.getClass();
        List<Field> encryptedFields = fieldCache.computeIfAbsent(clazz, this::getEncryptedFields);

        for (Field field : encryptedFields) {
            try {
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
        }
    }

    private List<Field> getEncryptedFields(Class<?> clazz) {
        List<Field> fields = new ArrayList<>();
        Class<?> current = clazz;
        while (current != null && current != Object.class) {
            for (Field field : current.getDeclaredFields()) {
                if (field.isAnnotationPresent(Encrypted.class)) {
                    field.setAccessible(true);
                    fields.add(field);
                }
            }
            current = current.getSuperclass();
        }
        return fields;
    }

    private boolean isEncrypted(String value) {
        if (value == null || value.isBlank()) return false;
        return value.startsWith(ENCRYPTED_PREFIX);
    }
}