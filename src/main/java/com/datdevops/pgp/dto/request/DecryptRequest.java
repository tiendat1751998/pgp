package com.datdevops.pgp.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record DecryptRequest(
    @NotBlank(message = "envelope is required")
    @Size(max = 2097152, message = "envelope must not exceed 2MB")
    String envelope
) {}