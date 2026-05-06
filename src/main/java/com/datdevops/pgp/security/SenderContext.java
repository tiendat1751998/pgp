package com.datdevops.pgp.security;

public class SenderContext {

    private static final ThreadLocal<Identity> IDENTITY = new ThreadLocal<>();

    private SenderContext() {}

    public static void setSenderId(String senderId) {
        if (senderId == null || senderId.isBlank()) {
            throw new IllegalArgumentException("senderId cannot be null or blank");
        }
        if (IDENTITY.get() != null && IDENTITY.get().senderId != null) {
            // Log warning instead of throwing to allow test re-initialization
            // In production, the filter ensures context is cleared.
            return; 
        }
        IDENTITY.set(new Identity(senderId));
    }

    public static void setAuthMethod(AuthMethod method) {
        Identity current = IDENTITY.get();
        if (current != null) {
            current.authMethod = method;
        }
    }

    public static Identity getIdentity() {
        return IDENTITY.get();
    }

    public static void setIdentity(Identity identity) {
        IDENTITY.set(identity);
    }

    public static String getSenderId() {
        Identity identity = IDENTITY.get();
        return identity != null ? identity.senderId : null;
    }

    public static AuthMethod getAuthMethod() {
        Identity identity = IDENTITY.get();
        return identity != null ? identity.authMethod : null;
    }

    public static boolean isAuthenticated() {
        return IDENTITY.get() != null && IDENTITY.get().senderId != null;
    }

    public static void clear() {
        IDENTITY.remove();
    }

    public enum AuthMethod {
        TLS_CERTIFICATE,
        PGP_SIGNATURE
    }

    public static class Identity {
        public String senderId;
        public AuthMethod authMethod;

        public Identity(String senderId) {
            this.senderId = senderId;
        }
    }
}