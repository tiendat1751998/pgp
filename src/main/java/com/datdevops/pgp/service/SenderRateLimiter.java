package com.datdevops.pgp.service;

import io.github.resilience4j.ratelimiter.RateLimiter;
import io.github.resilience4j.ratelimiter.RateLimiterConfig;
import io.github.resilience4j.ratelimiter.RateLimiterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class SenderRateLimiter {

    private static final Logger log = LoggerFactory.getLogger(SenderRateLimiter.class);

    private final RateLimiterRegistry rateLimiterRegistry;
    private final RateLimiterRegistry keyGenRateLimiterRegistry;
    private final ConcurrentHashMap<String, RateLimiter> limiters = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, RateLimiter> keyGenLimiters = new ConcurrentHashMap<>();

    @Value("${app.rate-limit.requests-per-second:1000}")
    private int requestsPerSecond;

    @Value("${app.rate-limit.timeout-ms:1000}")
    private int timeoutMs;

    @Value("${app.rate-limit.keygen-per-minute:5}")
    private int keyGenLimitPerMinute;

    public SenderRateLimiter() {
        RateLimiterConfig defaultConfig = RateLimiterConfig.custom()
                .limitRefreshPeriod(Duration.ofSeconds(1))
                .limitForPeriod(1000)
                .timeoutDuration(Duration.ofMillis(1000))
                .build();
        this.rateLimiterRegistry = RateLimiterRegistry.of(defaultConfig);
        
        // Separate limiter for key generation (CPU-intensive)
        RateLimiterConfig keyGenConfig = RateLimiterConfig.custom()
                .limitRefreshPeriod(Duration.ofMinutes(1))
                .limitForPeriod(5) // Only 5 key generations per minute per sender
                .timeoutDuration(Duration.ofMillis(5000)) // Wait up to 5 seconds
                .build();
        this.keyGenRateLimiterRegistry = RateLimiterRegistry.of(keyGenConfig);
    }

    public void checkRateLimit(String senderId) {
        RateLimiter limiter = limiters.computeIfAbsent(senderId, this::createLimiter);

        if (!limiter.acquirePermission()) {
            log.warn("[RATE_LIMIT] sender={} exceeded rate limit", senderId);
            throw new RuntimeException("Rate limit exceeded for sender: " + senderId);
        }
    }

    /**
     * Check rate limit for CPU-intensive operations (KEY GENERATION).
     * This prevents DoS via RSA key generation spam.
     */
    public void checkKeyGenRateLimit(String senderId) {
        RateLimiter limiter = keyGenLimiters.computeIfAbsent(senderId, this::createKeyGenLimiter);

        if (!limiter.acquirePermission()) {
            log.warn("[RATE_LIMIT_KEYGEN] sender={} exceeded key generation limit", senderId);
            throw new RuntimeException("Key generation rate limit exceeded. Try again later.");
        }
    }

    private RateLimiter createLimiter(String senderId) {
        RateLimiterConfig config = RateLimiterConfig.custom()
                .limitRefreshPeriod(Duration.ofSeconds(1))
                .limitForPeriod(requestsPerSecond)
                .timeoutDuration(Duration.ofMillis(timeoutMs))
                .build();
        return rateLimiterRegistry.rateLimiter(senderId, config);
    }

    private RateLimiter createKeyGenLimiter(String senderId) {
        RateLimiterConfig config = RateLimiterConfig.custom()
                .limitRefreshPeriod(Duration.ofMinutes(1))
                .limitForPeriod(keyGenLimitPerMinute)
                .timeoutDuration(Duration.ofMillis(5000))
                .build();
        return keyGenRateLimiterRegistry.rateLimiter(senderId + "-keygen", config);
    }

    public void clearLimiter(String senderId) {
        limiters.remove(senderId);
    }
}