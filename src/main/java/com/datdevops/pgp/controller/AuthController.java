package com.datdevops.pgp.controller;

import com.datdevops.pgp.security.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final JwtTokenProvider jwtTokenProvider;

    @Value("${app.auth.dev-mode:true}")
    private boolean devMode;

    public AuthController(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @PostMapping("/token")
    public ResponseEntity<Map<String, String>> generateToken(
            @RequestParam String username,
            @RequestParam(defaultValue = "USER") String role,
            @RequestParam(defaultValue = "3600000") long validityMs) {

        if (!devMode) {
            return ResponseEntity.status(403).body(Map.of(
                "error", "Token generation disabled in production"
            ));
        }

        String token = jwtTokenProvider.generateToken(username, role, validityMs);
        return ResponseEntity.ok(Map.of(
            "token", token,
            "type", "Bearer",
            "username", username,
            "role", role
        ));
    }

    @PostMapping("/admin-token")
    public ResponseEntity<Map<String, String>> generateAdminToken(
            @RequestParam String adminKey,
            @RequestParam(defaultValue = "3600000") long validityMs) {

        if (!devMode) {
            return ResponseEntity.status(403).body(Map.of(
                "error", "Token generation disabled in production"
            ));
        }

        if (!"admin-secret-key".equals(adminKey)) {
            return ResponseEntity.status(401).body(Map.of(
                "error", "Invalid admin key"
            ));
        }

        String token = jwtTokenProvider.generateToken("admin", "ADMIN", validityMs);
        return ResponseEntity.ok(Map.of(
            "token", token,
            "type", "Bearer",
            "role", "ADMIN"
        ));
    }
}