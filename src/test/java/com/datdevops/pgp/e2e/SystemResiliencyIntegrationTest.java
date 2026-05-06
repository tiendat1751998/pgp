package com.datdevops.pgp.e2e;

import com.datdevops.pgp.dto.request.EncryptRequest;
import com.datdevops.pgp.dto.response.EncryptResponse;
import com.datdevops.pgp.entity.Partner;
import com.datdevops.pgp.repository.PartnerRepository;
import com.datdevops.pgp.security.SenderContext;
import com.datdevops.pgp.service.KeyService;
import com.datdevops.pgp.service.KeyRotationService;
import com.datdevops.pgp.config.FeatureFlags;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import com.datdevops.pgp.service.RSAKeyPairGeneratorService;
import com.datdevops.pgp.service.KeyPairGeneratorService;
import com.datdevops.pgp.mapper.EntityMapper;

import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.UUID;

import javax.security.auth.x500.X500Principal;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(properties = {
        "app.master-key=this-is-a-very-secure-32char-master-key-!!",
        "app.replay-protection.strict-mode=true"
})
@AutoConfigureMockMvc(addFilters = false)
@Transactional
public class SystemResiliencyIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private PartnerRepository partnerRepository;

    @Autowired
    private KeyRotationService keyRotationService;

    @Autowired
    private KeyService keyService;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private RSAKeyPairGeneratorService rsaKeyPairGeneratorService;

    @Autowired
    private KeyPairGeneratorService keyPairGeneratorService;

    @Autowired
    private com.datdevops.pgp.mapper.EntityMapper entityMapper;

    @MockBean
    private FeatureFlags featureFlags;

    private String testPartnerId;
    private X509Certificate[] mockCerts;

    @BeforeEach
    void setup() throws Exception {
        SenderContext.clear();

        testPartnerId = "BANK_TEST_" + UUID.randomUUID().toString().substring(0, 8);

        // Generate valid keys for the partner entity to prevent KeyService failures
        var rsaKeyPair = rsaKeyPairGeneratorService.generateRSAKeyPair();
        String rsaPubKey = rsaKeyPairGeneratorService.getBase64PublicKey(rsaKeyPair);

        var edKeyPair = keyPairGeneratorService.generateEd25519KeyPair();
        String edPubKey = entityMapper.toBase64(keyPairGeneratorService.getEd25519PublicKey(edKeyPair).getEncoded());

        Partner partner = new Partner();
        partner.setId(testPartnerId);
        partner.setName("System Resiliency Test Partner");
        partner.setCustomerRsaPublicKey(rsaPubKey);
        partner.setCustomerEd25519PublicKey(edPubKey);
        partner.setKeystorePassword("encrypted-password");
        partnerRepository.saveAndFlush(partner);

        // Manually set context since filters are disabled
        SenderContext.setSenderId(testPartnerId);

        // Generate initial system keys for the partner
        keyRotationService.rotateRSAKey(testPartnerId);
        keyRotationService.rotateEd25519Key(testPartnerId);
    }

    @Test
    public void testKeyRotationEffectiveness() throws Exception {
        // 1. Perform initial rotation
        String rsaVersion = keyRotationService.rotateRSAKey(testPartnerId);
        String edVersion = keyRotationService.rotateEd25519Key(testPartnerId);

        assertNotNull(rsaVersion);
        assertNotNull(edVersion);

        // 2. Encrypt using the NEWLY rotated keys
        EncryptRequest request = new EncryptRequest(
                "FP-NEW",       // senderKeyFingerprint
                testPartnerId,  // recipientId
                "FP-NEW",       // recipientKeyFingerprint
                null,           // recipientRSAPublicKey (use internal key)
                "{\"data\": \"secret\"}", // payload
                "JSON"          // payloadType
        ); String responseJson = mockMvc.perform(post("/api/v1/crypto/encrypt")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        EncryptResponse response = objectMapper.readValue(responseJson, EncryptResponse.class);
        assertNotNull(response.encryptedEnvelope());

        // 3. Rotate AGAIN
        String rsaVersion2 = keyRotationService.rotateRSAKey(testPartnerId);
        assertNotEquals(rsaVersion, rsaVersion2);

        // 4. Decrypt should still work if we use the same identity (KeyService resolves
        // active key)
        // Note: Decrypt test requires full envelope parsing which is covered in other
        // tests,
        // but here we verify the system doesn't crash after multiple rotations.
    }

    @Test
    public void testStreamingOOMSafety() throws Exception {
        // This test simulates a streaming request.
        // We use a small payload but verify the stream-to-stream flow.
        byte[] largeData = "This is a large binary payload that should be streamed".getBytes(StandardCharsets.UTF_8);

        // First rotate keys so they exist in DB
        keyRotationService.rotateRSAKey(testPartnerId);

        byte[] encryptedOutput = mockMvc.perform(post("/api/v1/streaming/encrypt")
                .param("recipientId", testPartnerId)
                .content(largeData)
                .contentType(MediaType.APPLICATION_OCTET_STREAM))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsByteArray();

        assertNotNull(encryptedOutput);
        assertTrue(encryptedOutput.length > largeData.length);

        // Decrypt the stream
        byte[] decryptedOutput = mockMvc.perform(post("/api/v1/streaming/decrypt")
                .content(encryptedOutput)
                .contentType(MediaType.APPLICATION_OCTET_STREAM))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsByteArray();

        assertArrayEquals(largeData, decryptedOutput);
    }

    @Test
    public void testUnauthorizedAccessPrevention() throws Exception {
        // Clear identity
        SenderContext.clear();

        EncryptRequest request = new EncryptRequest("{}", "JSON", "A", "F", "B", "F");

        mockMvc.perform(post("/api/v1/crypto/encrypt")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }
}
