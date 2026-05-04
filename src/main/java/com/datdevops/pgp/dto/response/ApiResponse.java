package com.datdevops.pgp.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiResponse<T>(
    String status,
    String message,
    T data,
    String traceId,
    Long timestamp
) {
    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse("SUCCESS", null, data, null, System.currentTimeMillis());
    }

    public static <T> ApiResponse<T> success(String message, T data) {
        return new ApiResponse("SUCCESS", message, data, null, System.currentTimeMillis());
    }

    public static <T> ApiResponse<T> error(String message) {
        return new ApiResponse("ERROR", message, null, null, System.currentTimeMillis());
    }

    public static <T> ApiResponse<T> error(String message, String traceId) {
        return new ApiResponse("ERROR", message, null, traceId, System.currentTimeMillis());
    }
}