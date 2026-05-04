package com.datdevops.pgp.controller;

import com.datdevops.pgp.dto.response.AdminPasswordResponse;
import com.datdevops.pgp.entity.Partner;
import com.datdevops.pgp.service.PartnerService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/partners")
public class PartnerController {

    private final PartnerService partnerService;

    public PartnerController(PartnerService partnerService) {
        this.partnerService = partnerService;
    }

    @PostMapping("/onboard")
    public ResponseEntity<com.datdevops.pgp.dto.response.PartnerOnboardResponse> onboardPartner(@RequestBody Partner partner) throws Exception {
        return ResponseEntity.ok(partnerService.onboardPartner(
                partner.getId(),
                partner.getName(),
                partner.getCustomerRsaPublicKey(),
                partner.getCustomerEd25519PublicKey()
        ));
    }

    @PutMapping("/{id}/password")
    public ResponseEntity<Void> updatePassword(@PathVariable String id, @RequestBody String newPassword) throws Exception {
        partnerService.updateKeystorePassword(id, newPassword);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/{id}/admin-password")
    public ResponseEntity<AdminPasswordResponse> getAdminEncryptedPassword(@PathVariable String id) {
        return partnerService.getPartner(id)
                .map(partner -> {
                    boolean hasPassword = partner.getAdminEncryptedKeystorePassword() != null 
                        && !partner.getAdminEncryptedKeystorePassword().isEmpty();
                    AdminPasswordResponse response = new AdminPasswordResponse(
                        partner.getId(),
                        hasPassword,
                        hasPassword ? "Admin password configured" : "Not configured"
                    );
                    return ResponseEntity.ok(response);
                })
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/{id}")
    public ResponseEntity<Partner> getPartner(@PathVariable String id) {
        return partnerService.getPartner(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping
    public ResponseEntity<List<Partner>> getAllPartners() {
        return ResponseEntity.ok(partnerService.getAllPartners());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deletePartner(@PathVariable String id) {
        partnerService.removePartner(id);
        return ResponseEntity.ok().build();
    }
}
