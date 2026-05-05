package com.datdevops.pgp.controller;

import com.datdevops.pgp.security.SenderContext;
import com.datdevops.pgp.service.KeyRotationService;
import com.datdevops.pgp.dto.response.ApiResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/keys")
public class KeyRotationController {
    private static final Logger log = LoggerFactory.getLogger(KeyRotationController.class);

    private final KeyRotationService keyRotationService;

    public KeyRotationController(KeyRotationService keyRotationService) {
        this.keyRotationService = keyRotationService;
    }

    /**
     * Triggers rotation for our own RSA key.
     */
    @PostMapping("/rotate/rsa")
    public ResponseEntity<ApiResponse<String>> rotateRSA() {
        String partnerId = SenderContext.getSenderId();
        if (partnerId == null) return ResponseEntity.status(403).build();

        try {
            log.info("[KEY_MGMT] Manual RSA rotation triggered for: {}", partnerId);
            String newKeyVersion = keyRotationService.rotateRSAKey(partnerId);
            return ResponseEntity.ok(ApiResponse.success("RSA key rotated successfully: " + newKeyVersion, null));
        } catch (Exception e) {
            log.error("[ERROR] RSA rotation failed", e);
            return ResponseEntity.internalServerError().body(ApiResponse.error(e.getMessage()));
        }
    }

    /**
     * Triggers rotation for our own Ed25519 signing key.
     */
    @PostMapping("/rotate/ed25519")
    public ResponseEntity<ApiResponse<String>> rotateEd25519() {
        String partnerId = SenderContext.getSenderId();
        if (partnerId == null) return ResponseEntity.status(403).build();

        try {
            log.info("[KEY_MGMT] Manual Ed25519 rotation triggered for: {}", partnerId);
            String newKeyVersion = keyRotationService.rotateEd25519Key(partnerId);
            return ResponseEntity.ok(ApiResponse.success("Ed25519 key rotated successfully: " + newKeyVersion, null));
        } catch (Exception e) {
            log.error("[ERROR] Ed25519 rotation failed", e);
            return ResponseEntity.internalServerError().body(ApiResponse.error(e.getMessage()));
        }
    }

    @GetMapping("/history")
    public ResponseEntity<ApiResponse<Object>> getHistory(@RequestParam String type) {
        String partnerId = SenderContext.getSenderId();
        if (partnerId == null) return ResponseEntity.status(403).build();

        var history = keyRotationService.getKeyHistory(partnerId, type);
        return ResponseEntity.ok(ApiResponse.success("Success", history));
    }
}
