package com.datdevops.pgp.dto.internal;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record PartnerDto(
    @NotBlank(message = "Partner ID is required")
    @Pattern(regexp = "^[a-zA-Z0-9_-]+$", message = "Partner ID must be alphanumeric, underscore or hyphen only")
    @Size(max = 64, message = "Partner ID max 64 characters")
    String partnerId,

    @Size(max = 255, message = "Partner name max 255 characters")
    String partnerName,

    String customerEd25519PublicKey,

    String customerRsaPublicKey,

    String keyFingerprint,

    String internalKeystorePassword,

    boolean active,

    Long createdAt,

    Long updatedAt
) {}