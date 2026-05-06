package com.datdevops.pgp.security;

import com.datdevops.pgp.config.FeatureFlags;
import com.datdevops.pgp.service.PartnerService;
import com.datdevops.pgp.service.SenderRateLimiter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.security.Principal;
import java.security.cert.X509Certificate;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * RED TEAM ATTACK: Log Forging / Injection via mTLS
 * Objective: Demonstrate that a malicious CN in a certificate can inject 
 * newline characters into logs, allowing an attacker to forge audit entries.
 */
public class LogForgeAttack {

    @Test
    public void attack_LogInjection() throws Exception {
        System.out.println(">>> STARTING LOG INJECTION ATTACK...");

        // 1. Setup mocks
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain filterChain = mock(FilterChain.class);
        
        X509Certificate mockCert = mock(X509Certificate.class);
        Principal mockPrincipal = mock(Principal.class);
        
        // 2. Craft a malicious CN with newlines
        // In a real log, this would look like two separate entries.
        String maliciousCn = "LEGIT_PARTNER\n[INFO] [AUTH] mTLS authenticated | sender=ADMIN | path=/api/v1/admin/delete-all";
        
        when(mockPrincipal.getName()).thenReturn("CN=" + maliciousCn);
        when(mockCert.getSubjectX500Principal()).thenReturn(new javax.security.auth.x500.X500Principal("CN=" + maliciousCn));
        
        X509Certificate[] certs = new X509Certificate[]{mockCert};
        when(request.getAttribute("javax.servlet.request.X509Certificate")).thenReturn(certs);
        when(request.getRequestURI()).thenReturn("/api/v1/crypto/encrypt");

        // 3. Setup filter dependencies
        FeatureFlags flags = mock(FeatureFlags.class);
        when(flags.isMtlsEnabled()).thenReturn(true);
        
        PartnerService partnerService = mock(PartnerService.class);
        // Ensure the malicious ID "passes" as a partner for the sake of the test
        when(partnerService.getPartner(anyString())).thenReturn(java.util.Optional.of(new com.datdevops.pgp.entity.Partner()));
        
        SenderRateLimiter rateLimiter = mock(SenderRateLimiter.class);
        MeterRegistry registry = new SimpleMeterRegistry();

        MTLSAuthenticationFilter filter = new MTLSAuthenticationFilter(flags, partnerService, rateLimiter, registry, "");

        // 4. Execute filter
        System.out.println("[+] Executing filter with malicious certificate...");
        filter.doFilterInternal(request, response, filterChain);

        System.out.println(">>> ATTACK DEMONSTRATION COMPLETE.");
        System.out.println("[!] Check console logs above. If you see a forged 'ADMIN' entry, the attack succeeded.");
    }
}
