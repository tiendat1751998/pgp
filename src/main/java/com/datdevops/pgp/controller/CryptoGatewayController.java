package com.datdevops.pgp.controller;

import com.datdevops.pgp.dto.request.DecryptRequest;
import com.datdevops.pgp.dto.request.EncryptRequest;
import com.datdevops.pgp.dto.response.DecryptResponse;
import com.datdevops.pgp.dto.response.EncryptResponse;
import com.datdevops.pgp.service.CryptoApplicationService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/crypto")
public class CryptoGatewayController {

    private static final Logger log = LoggerFactory.getLogger(CryptoGatewayController.class);

    private final CryptoApplicationService cryptoApplicationService;

    public CryptoGatewayController(CryptoApplicationService cryptoApplicationService) {
        this.cryptoApplicationService = cryptoApplicationService;
    }

    @PostMapping("/encrypt")
    public ResponseEntity<EncryptResponse> encrypt(@Valid @RequestBody EncryptRequest request) {
        try {
            EncryptResponse response = cryptoApplicationService.encrypt(request);
            return ResponseEntity.ok(response);
        } catch (SecurityException e) {
            log.warn("[SECURITY] Encrypt blocked: {}", e.getMessage());
            return ResponseEntity.status(403).build();
        } catch (Exception e) {
            log.error("[ERROR] Encrypt failed", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @PostMapping("/decrypt")
    public ResponseEntity<DecryptResponse> decrypt(@Valid @RequestBody DecryptRequest request) {
        try {
            DecryptResponse response = cryptoApplicationService.decrypt(request);
            return ResponseEntity.ok(response);
        } catch (SecurityException e) {
            log.warn("[SECURITY] Decrypt blocked: {}", e.getMessage());
            return ResponseEntity.status(403).build();
        } catch (Exception e) {
            log.error("[ERROR] Decrypt failed", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> status = new HashMap<>();
        status.put("status", "UP");
        status.put("service", "crypto-gateway");
        status.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(status);
    }
}