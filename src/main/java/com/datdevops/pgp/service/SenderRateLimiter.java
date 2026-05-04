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
    private final ConcurrentHashMap<String, RateLimiter> limiters = new ConcurrentHashMap<>();

    @Value("${app.rate-limit.requests-per-second:1000}")
    private int requestsPerSecond;

    @Value("${app.rate-limit.timeout-ms:1000}")
    private int timeoutMs;

    public SenderRateLimiter() {
        RateLimiterConfig defaultConfig = RateLimiterConfig.custom()
                .limitRefreshPeriod(Duration.ofSeconds(1))
                .limitForPeriod(1000)
                .timeoutDuration(Duration.ofMillis(1000))
                .build();
        this.rateLimiterRegistry = RateLimiterRegistry.of(defaultConfig);
    }

    public void checkRateLimit(String senderId) {
        RateLimiter limiter = limiters.computeIfAbsent(senderId, this::createLimiter);

        if (!limiter.acquirePermission()) {
            log.warn("[RATE_LIMIT] sender={} exceeded rate limit", senderId);
            throw new RuntimeException("Rate limit exceeded for sender: " + senderId);
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

    public void clearLimiter(String senderId) {
        limiters.remove(senderId);
    }
}