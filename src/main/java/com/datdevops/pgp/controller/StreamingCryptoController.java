package com.datdevops.pgp.controller;

import com.datdevops.pgp.service.StreamingCryptoService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/streaming")
public class StreamingCryptoController {
    private static final Logger log = LoggerFactory.getLogger(StreamingCryptoController.class);

    private final StreamingCryptoService streamingCryptoService;

    public StreamingCryptoController(StreamingCryptoService streamingCryptoService) {
        this.streamingCryptoService = streamingCryptoService;
    }

    /**
     * Encrypts a raw binary stream.
     * Use: curl -X POST --data-binary @large_file.bin
     * "http://host/api/v1/streaming/encrypt?recipientId=BANK_B"
     */
    @PostMapping("/encrypt")
    public void encrypt(@RequestParam String recipientId, HttpServletRequest request, HttpServletResponse response) {
        try {
            response.setContentType("application/octet-stream");
            streamingCryptoService.encryptStream(request.getInputStream(), response.getOutputStream(), recipientId);
        } catch (SecurityException e) {
            log.warn("[SECURITY] Streaming encrypt blocked: {}", e.getMessage());
            response.setStatus(403);
        } catch (Exception e) {
            e.printStackTrace();
            response.setStatus(500);
        }
    }

    /**
     * Decrypts a raw binary stream.
     */
    @PostMapping("/decrypt")
    public void decrypt(HttpServletRequest request, HttpServletResponse response) {
        try {
            response.setContentType("application/octet-stream");
            streamingCryptoService.decryptStream(request.getInputStream(), response.getOutputStream());
        } catch (SecurityException e) {
            log.warn("[SECURITY] Streaming decrypt blocked: {}", e.getMessage());
            response.setStatus(403);
        } catch (Exception e) {
            e.printStackTrace();
            response.setStatus(500);
        }
    }
}
