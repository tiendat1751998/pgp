package com.datdevops.pgp.dto.response;

public record AdminPasswordResponse(
    String partnerId,
    boolean hasAdminPassword,
    String message
) {}