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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.io.IOException;
import java.net.URL;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Component
@org.springframework.core.annotation.Order(org.springframework.core.Ordered.HIGHEST_PRECEDENCE + 100)
public class MTLSAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(MTLSAuthenticationFilter.class);

    private static final Pattern SAFE_SENDER_ID_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]+$");
    private static final int MAX_SENDER_ID_LENGTH = 64;

    private final FeatureFlags featureFlags;
    private final PartnerService partnerService;
    private final SenderRateLimiter senderRateLimiter;
    private final Set<String> allowedSenders;

    private final Counter mtlsAuthSuccess;
    private final Counter mtlsAuthFailure;
    private final Cache<String, X509CRL> crlCache;
    private final String trustedIssuerDn;

    public MTLSAuthenticationFilter(
            FeatureFlags featureFlags,
            PartnerService partnerService,
            SenderRateLimiter senderRateLimiter,
            MeterRegistry meterRegistry,
            @Value("${app.mtls.allowed-senders:}") String allowedSendersConfig,
            @Value("${app.mtls.trusted-issuer-dn:}") String trustedIssuerDn) {
        this.featureFlags = featureFlags;
        this.partnerService = partnerService;
        this.senderRateLimiter = senderRateLimiter;
        this.trustedIssuerDn = trustedIssuerDn;

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

        this.crlCache = Caffeine.newBuilder()
                .expireAfterWrite(60, TimeUnit.MINUTES)
                .maximumSize(10)
                .build();
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

            X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
            if (certs != null && certs.length > 0) {
                String revocationError = validateCertificateRevocation(certs[0]);
                if (revocationError != null) {
                    log.warn("[AUTH] Certificate validation failed: {} | sender={} | path={}", revocationError, senderId, request.getRequestURI());
                    mtlsAuthFailure.increment();
                    sendUnauthorized(response, "Certificate validation failed: " + revocationError);
                    return;
                }
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

            // CRITICAL: Set Spring SecurityContext to prevent 403 Forbidden
            UsernamePasswordAuthenticationToken springAuth = new UsernamePasswordAuthenticationToken(
                    senderId,
                    null,
                    List.of(new SimpleGrantedAuthority("ROLE_PARTNER"))
            );
            springAuth.setDetails(request);
            SecurityContextHolder.getContext().setAuthentication(springAuth);

            mtlsAuthSuccess.increment();
            log.info("[AUTH] mTLS authenticated | sender={} | path={}", senderId, request.getRequestURI());
            log.trace("[AUTH] Context set: senderId={}, SpringSecurity={}", SenderContext.getSenderId(), springAuth.isAuthenticated());

            filterChain.doFilter(request, response);
        } finally {
            log.trace("[AUTH] Clearing context for senderId={}", SenderContext.getSenderId());
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
            return sanitizeSenderId(cn);
        }

        String rawName = clientCert.getSubjectX500Principal().getName();
        return sanitizeSenderId(rawName);
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

    /**
     * Sanitizes sender ID to prevent Log Forging / Injection attacks.
     * - Removes newline characters (\r, \n)
     * - Truncates to max length
     * - Validates against safe pattern
     */
    private String sanitizeSenderId(String rawSenderId) {
        if (rawSenderId == null || rawSenderId.isBlank()) {
            return null;
        }

        String sanitized = rawSenderId
                .replace("\r", "")
                .replace("\n", "")
                .replace("\t", "")
                .trim();

        if (sanitized.length() > MAX_SENDER_ID_LENGTH) {
            sanitized = sanitized.substring(0, MAX_SENDER_ID_LENGTH);
        }

        if (!SAFE_SENDER_ID_PATTERN.matcher(sanitized).matches()) {
            log.warn("[AUTH] Invalid sender ID pattern detected - rejecting");
            return null;
        }

        return sanitized;
    }

    /**
     * Validates certificate revocation status.
     * Checks:
     * 1. Certificate is not expired
     * 2. Certificate is not yet valid
     * 3. CRL (Certificate Revocation List) check
     */
    private String validateCertificateRevocation(X509Certificate cert) {
        Date now = new Date();

        if (cert.getNotBefore() != null && now.before(cert.getNotBefore())) {
            return "Certificate not yet valid";
        }

        if (cert.getNotAfter() != null && now.after(cert.getNotAfter())) {
            return "Certificate has expired";
        }

        // CRITICAL: Trust Anchor Validation - Use strict equality to prevent spoofing
        if (trustedIssuerDn != null && !trustedIssuerDn.isBlank()) {
            String issuerDn = cert.getIssuerX500Principal().getName();
            // Using equals on the principal is safer than contains() on the string representation
            if (!cert.getIssuerX500Principal().getName().equals(trustedIssuerDn)) {
                log.error("[SECURITY_BREACH] Unauthorized Issuer: {} | Expected: {}", sanitizeForLog(issuerDn), trustedIssuerDn);
                return "Certificate issued by untrusted authority";
            }
        }

        try {
            String crlError = checkCRL(cert);
            if (crlError != null) {
                return crlError;
            }
        } catch (Exception e) {
            log.error("[AUTH] CRL validation error: {}", e.getMessage());
            return "Certificate revocation check failed";
        }

        return null;
    }

    private String checkCRL(X509Certificate cert) {
        try {
            String crlUrl = System.getenv("CRL_DP_URL");
            if (crlUrl == null || crlUrl.isBlank()) {
                log.warn("[SECURITY] CRL_URL not configured - FAIL-CLOSE POLICY ENFORCED");
                return "Revocation infrastructure unavailable";
            }

            X509CRL crl = crlCache.get(crlUrl, urlKey -> {
                try {
                    log.info("[AUTH] Refreshing CRL from URL: {}", urlKey);
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    URL url = new URL(urlKey);
                    return (X509CRL) cf.generateCRL(url.openStream());
                } catch (Exception e) {
                    log.error("[AUTH] Failed to fetch CRL from {}: {}", urlKey, e.getMessage());
                    return null;
                }
            });

            if (crl != null && crl.isRevoked(cert)) {
                log.error("[AUTH] Certificate REVOKED per CRL: {}", sanitizeForLog(cert.getSubjectX500Principal().getName()));
                return "Certificate has been revoked";
            }
        } catch (Exception e) {
            log.warn("[AUTH] CRL check failed: {}", e.getMessage());
        }
        return null;
    }

    private String sanitizeForLog(String input) {
        if (input == null) return "null";
        return input.replace("\n", "_").replace("\r", "_").replace("\t", "_");
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

