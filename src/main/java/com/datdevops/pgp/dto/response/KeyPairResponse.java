package com.datdevops.pgp.dto.response;

public record KeyPairResponse(
    String ed25519PrivateKey,
    String ed25519PublicKey,
    String rsaPublicKey,
    String rsaPrivateKey
) {}