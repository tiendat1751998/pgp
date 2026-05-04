package com.datdevops.pgp.dto.response;

public record TokenResponse(
    String token,
    String type,
    String username,
    String role,
    Long expiresIn
) {}