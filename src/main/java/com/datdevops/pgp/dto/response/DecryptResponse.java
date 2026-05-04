package com.datdevops.pgp.dto.response;

public record DecryptResponse(
    String messageType,
    String payload
) {}