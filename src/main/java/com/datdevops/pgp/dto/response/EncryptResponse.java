package com.datdevops.pgp.dto.response;

public record EncryptResponse(
    String messageId,
    String encryptedEnvelope,
    String timestamp
) {}