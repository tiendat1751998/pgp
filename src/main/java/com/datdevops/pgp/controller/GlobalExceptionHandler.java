package com.datdevops.pgp.controller;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.NoHandlerFoundException;

import java.util.Map;
import java.util.UUID;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    private final Counter error4xxCounter;
    private final Counter error5xxCounter;

    public GlobalExceptionHandler(MeterRegistry meterRegistry) {
        this.error4xxCounter = Counter.builder("http.errors")
                .tag("status", "4xx")
                .register(meterRegistry);
        this.error5xxCounter = Counter.builder("http.errors")
                .tag("status", "5xx")
                .register(meterRegistry);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<Map<String, Object>> handleValidationException(ConstraintViolationException ex) {
        String traceId = MDC.get("traceId");
        if (traceId == null) traceId = UUID.randomUUID().toString();

        error4xxCounter.increment();
        log.warn("[VALIDATION_ERROR] traceId={} message={}", traceId, ex.getMessage());

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                "error", "Validation Error",
                "message", ex.getMessage(),
                "traceId", traceId
        ));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleBadRequest(IllegalArgumentException ex) {
        String traceId = MDC.get("traceId");
        if (traceId == null) traceId = UUID.randomUUID().toString();

        error4xxCounter.increment();
        log.warn("[BAD_REQUEST] traceId={} message={}", traceId, ex.getMessage());

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                "error", "Bad Request",
                "message", ex.getMessage(),
                "traceId", traceId
        ));
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<Map<String, Object>> handleTypeMismatch(MethodArgumentTypeMismatchException ex) {
        String traceId = UUID.randomUUID().toString();
        error4xxCounter.increment();
        
        log.warn("[TYPE_MISMATCH] traceId={} message={}", traceId, ex.getMessage());

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                "error", "Type Mismatch",
                "message", "Invalid parameter type",
                "traceId", traceId
        ));
    }

    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<Map<String, Object>> handleNotFound(NoHandlerFoundException ex) {
        String traceId = UUID.randomUUID().toString();
        error4xxCounter.increment();
        
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of(
                "error", "Not Found",
                "message", "Endpoint not found",
                "traceId", traceId
        ));
    }

    @ExceptionHandler(SecurityException.class)
    public ResponseEntity<Map<String, Object>> handleSecurityException(SecurityException ex) {
        String traceId = MDC.get("traceId");
        if (traceId == null) traceId = UUID.randomUUID().toString();

        error4xxCounter.increment();
        log.warn("[SECURITY] traceId={} message={}", traceId, ex.getMessage());

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                "error", "Security Error",
                "message", "Access denied",
                "traceId", traceId
        ));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGenericException(Exception ex) {
        String traceId = MDC.get("traceId");
        if (traceId == null) traceId = UUID.randomUUID().toString();

        error5xxCounter.increment();
        log.error("[INTERNAL_ERROR] traceId={} message={}", traceId, ex.getMessage(), ex);

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                "error", "Internal Server Error",
                "message", "An unexpected error occurred",
                "traceId", traceId
        ));
    }
}