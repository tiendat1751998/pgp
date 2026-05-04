package com.datdevops.pgp.dto.internal;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record KeyInfoDto(
    @NotBlank(message = "Partner ID is required")
    @Pattern(regexp = "^[a-zA-Z0-9_-]+$", message = "Partner ID must be alphanumeric only")
    String partnerId,

    String keystoreFileName,

    String keyAlias,

    String keyType,

    String fingerprint,

    Long keyVersion,

    String createdAt,

    Long expiresAt
) {}