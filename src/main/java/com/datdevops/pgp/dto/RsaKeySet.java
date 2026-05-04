package com.datdevops.pgp.dto;

public record RsaKeySet(
    String publicKey,
    String privateKey,
    String keyId,
    long createdAt,
    boolean active
) {}