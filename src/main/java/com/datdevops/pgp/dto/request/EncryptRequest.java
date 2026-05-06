package com.datdevops.pgp.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record EncryptRequest(
    @NotBlank(message = "recipientId is required")
    @Size(max = 100, message = "recipientId must not exceed 100 characters")
    String recipientId,

    @NotBlank(message = "payload is required")
    @Size(max = 1048576, message = "payload must not exceed 1MB")
    String payload,

    @NotBlank(message = "payloadType is required")
    @Size(max = 50, message = "payloadType must not exceed 50 characters")
    String payloadType
) {}