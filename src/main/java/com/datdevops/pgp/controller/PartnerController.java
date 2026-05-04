package com.datdevops.pgp.controller;

import com.datdevops.pgp.dto.internal.PartnerDto;
import com.datdevops.pgp.dto.request.PartnerOnboardRequest;
import com.datdevops.pgp.dto.response.ApiResponse;
import com.datdevops.pgp.dto.response.PartnerOnboardResponse;
import com.datdevops.pgp.security.SenderContext;
import com.datdevops.pgp.service.AuditService;
import com.datdevops.pgp.service.PartnerService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Partner management controller.
 * All operations require mTLS authentication.
 * Partners can only access their own data (identity-scoped).
 */
@RestController
@RequestMapping("/api/v1/partners")
public class PartnerController {

    private static final Logger log = LoggerFactory.getLogger(PartnerController.class);

    private final PartnerService partnerService;
    private final AuditService auditService;

    public PartnerController(PartnerService partnerService, AuditService auditService) {
        this.partnerService = partnerService;
        this.auditService = auditService;
    }

    /**
     * Onboard a new partner.
     * The authenticated sender's CN must match the partner ID being onboarded.
     */
    @PostMapping("/onboard")
    public ResponseEntity<ApiResponse<PartnerOnboardResponse>> onboardPartner(
            @Valid @RequestBody PartnerOnboardRequest request) throws Exception {
        String authenticatedId = requireAuthentication();

        PartnerOnboardResponse response = partnerService.onboardPartner(
                authenticatedId,
                request.name(),
                request.customerRsaPublicKey(),
                request.customerEd25519PublicKey()
        );

        auditService.logSecurityEvent(authenticatedId, "PARTNER_ONBOARD", "Partner onboarded: " + authenticatedId);
        return ResponseEntity.ok(ApiResponse.success("Partner onboarded successfully", response));
    }

    /**
     * Get partner details. Partners can only view their own data.
     */
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<PartnerDto>> getPartner() {
        String authenticatedId = requireAuthentication();

        return partnerService.getPartnerDto(authenticatedId)
                .map(dto -> ResponseEntity.ok(ApiResponse.success(dto)))
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Update keystore password. Partners can only update their own password.
     */
    @PutMapping("/me/password")
    public ResponseEntity<ApiResponse<Void>> updatePassword(
            @RequestBody String newPassword) throws Exception {
        String authenticatedId = requireAuthentication();

        partnerService.updateKeystorePassword(authenticatedId, newPassword);
        auditService.logSecurityEvent(authenticatedId, "PASSWORD_UPDATE", "Keystore password updated for: " + authenticatedId);
        return ResponseEntity.ok(ApiResponse.success("Password updated successfully", null));
    }

    /**
     * Delete partner. Partners can only delete themselves.
     */
    @DeleteMapping("/me")
    public ResponseEntity<ApiResponse<Void>> deletePartner() {
        String authenticatedId = requireAuthentication();

        partnerService.removePartner(authenticatedId);
        auditService.logSecurityEvent(authenticatedId, "PARTNER_DELETE", "Partner deleted: " + authenticatedId);
        return ResponseEntity.ok(ApiResponse.success("Partner deleted successfully", null));
    }

    // --- Security Helpers ---

    private String requireAuthentication() {
        String senderId = SenderContext.getSenderId();
        if (senderId == null || senderId.isBlank()) {
            throw new SecurityException("Unauthorized: No authenticated identity");
        }
        return senderId;
    }

    // Ownership validation is no longer needed since we derive identity securely.
}
