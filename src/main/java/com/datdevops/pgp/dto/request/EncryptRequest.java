package com.datdevops.pgp.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record EncryptRequest(
    @Size(max = 256, message = "senderKeyFingerprint must not exceed 256 characters")
    String senderKeyFingerprint,

    @NotBlank(message = "recipientId is required")
    @Size(max = 100, message = "recipientId must not exceed 100 characters")
    String recipientId,

    @Size(max = 256, message = "recipientKeyFingerprint must not exceed 256 characters")
    String recipientKeyFingerprint,

    @Size(max = 10000, message = "recipientRSAPublicKey is too large")
    String recipientRSAPublicKey,

    @NotBlank(message = "payload is required")
    @Size(max = 1048576, message = "payload must not exceed 1MB")
    String payload,

    @NotBlank(message = "payloadType is required")
    @Size(max = 50, message = "payloadType must not exceed 50 characters")
    String payloadType
) {}