package com.datdevops.pgp.security;

import com.datdevops.pgp.config.FeatureFlags;
import com.datdevops.pgp.service.PartnerService;
import com.datdevops.pgp.service.SenderRateLimiter;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.stream.Collectors;

@Component
@org.springframework.core.annotation.Order(org.springframework.core.Ordered.HIGHEST_PRECEDENCE + 100)
public class MTLSAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(MTLSAuthenticationFilter.class);

    private final FeatureFlags featureFlags;
    private final PartnerService partnerService;
    private final SenderRateLimiter senderRateLimiter;
    private final Set<String> allowedSenders;

    private final Counter mtlsAuthSuccess;
    private final Counter mtlsAuthFailure;

    public MTLSAuthenticationFilter(
            FeatureFlags featureFlags,
            PartnerService partnerService,
            SenderRateLimiter senderRateLimiter,
            MeterRegistry meterRegistry,
            @Value("${app.mtls.allowed-senders:}") String allowedSendersConfig) {
        this.featureFlags = featureFlags;
        this.partnerService = partnerService;
        this.senderRateLimiter = senderRateLimiter;

        if (allowedSendersConfig != null && !allowedSendersConfig.isBlank()) {
            this.allowedSenders = Set.of(allowedSendersConfig.split(",")).stream()
                    .map(String::trim)
                    .collect(Collectors.toSet());
        } else {
            this.allowedSenders = Set.of();
        }

        this.mtlsAuthSuccess = Counter.builder("auth.mtls.success")
                .description("Successful mTLS authentications")
                .register(meterRegistry);
        this.mtlsAuthFailure = Counter.builder("auth.mtls.failure")
                .description("Failed mTLS authentications")
                .register(meterRegistry);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        long startTime = System.currentTimeMillis();

        try {
            if (!featureFlags.isMtlsEnabled()) {
                log.warn("[AUTH] mTLS is disabled - rejecting request | path={}", request.getRequestURI());
                mtlsAuthFailure.increment();
                sendUnauthorized(response, "mTLS authentication is required");
                return;
            }

            String senderId = extractSenderIdFromCertificate(request);

            if (senderId == null) {
                log.warn("[AUTH] No valid client certificate | path={}", request.getRequestURI());
                mtlsAuthFailure.increment();
                sendUnauthorized(response, "Valid client certificate required");
                return;
            }

            // Allowlist check (if configured)
            if (!allowedSenders.isEmpty() && !allowedSenders.contains(senderId)) {
                log.warn("[AUTH] Sender not in allowlist | sender={} | path={}", senderId, request.getRequestURI());
                mtlsAuthFailure.increment();
                sendUnauthorized(response, "Sender not authorized");
                return;
            }

            // Verify sender is a registered partner
            if (partnerService.getPartner(senderId).isEmpty()) {
                log.warn("[AUTH] Sender is not a registered partner | sender={} | path={}", senderId, request.getRequestURI());
                mtlsAuthFailure.increment();
                sendUnauthorized(response, "Unknown partner");
                return;
            }

            // Rate limit check
            try {
                senderRateLimiter.checkRateLimit(senderId);
            } catch (Exception e) {
                log.warn("[AUTH] Rate limit exceeded | sender={}", senderId);
                response.setStatus(429);
                response.setContentType("application/json");
                response.getWriter().write("{\"error\":\"Rate limit exceeded\"}");
                return;
            }

            // Set identity context
            SenderContext.setSenderId(senderId);
            SenderContext.setAuthMethod(SenderContext.AuthMethod.TLS_CERTIFICATE);
            mtlsAuthSuccess.increment();
            log.info("[AUTH] mTLS authenticated | sender={} | path={}", senderId, request.getRequestURI());

            filterChain.doFilter(request, response);
        } finally {
            long duration = System.currentTimeMillis() - startTime;
            log.debug("[AUTH] duration={}ms | path={}", duration, request.getRequestURI());
            SenderContext.clear();
        }
    }

    private String extractSenderIdFromCertificate(HttpServletRequest request) {
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");

        if (certs == null || certs.length == 0) {
            return null;
        }

        X509Certificate clientCert = certs[0];
        if (clientCert == null) {
            return null;
        }

        String cn = extractCN(clientCert);
        if (cn != null && !cn.isBlank()) {
            return cn;
        }

        return clientCert.getSubjectX500Principal().getName();
    }

    private String extractCN(X509Certificate cert) {
        String subject = cert.getSubjectX500Principal().getName();
        if (subject == null || subject.isBlank()) {
            return null;
        }

        int cnStart = subject.indexOf("CN=");
        if (cnStart < 0) {
            return null;
        }

        int cnEnd = subject.indexOf(",", cnStart);
        if (cnEnd > cnStart) {
            return subject.substring(cnStart + 3, cnEnd).trim();
        }
        return subject.substring(cnStart + 3).trim();
    }

    private void sendUnauthorized(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"" + message + "\"}");
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/actuator/") || path.equals("/api/v1/crypto/health");
    }
}

