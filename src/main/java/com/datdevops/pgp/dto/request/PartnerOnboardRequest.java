package com.datdevops.pgp.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PartnerOnboardRequest(
    @NotBlank(message = "Partner name is required")
    @Size(max = 255, message = "Partner name max 255 characters")
    String name,

    @Size(max = 4096, message = "Customer RSA public key is too large")
    String customerRsaPublicKey,

    @Size(max = 2048, message = "Customer Ed25519 public key is too large")
    String customerEd25519PublicKey
) {}