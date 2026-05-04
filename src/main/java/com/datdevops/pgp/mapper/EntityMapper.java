package com.datdevops.pgp.mapper;

import com.datdevops.pgp.dto.internal.PartnerDto;
import com.datdevops.pgp.dto.request.*;
import com.datdevops.pgp.dto.response.*;
import com.datdevops.pgp.entity.Partner;
import com.datdevops.pgp.model.SecureEnvelope;
import com.datdevops.pgp.config.CryptoConfig;
import com.datdevops.pgp.util.RsaKeyUtils;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.springframework.stereotype.Component;

import java.security.PublicKey;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Map;

@Component
public class EntityMapper {

    public EntityMapper() {
        new CryptoConfig();
    }

    public EncryptRequest toEncryptRequest(String senderId, String senderKeyFingerprint,
            String recipientId, String recipientKeyFingerprint,
            String recipientRSAPublicKey, String payload, String payloadType) {
        return new EncryptRequest(senderId, senderKeyFingerprint,
                recipientId, recipientKeyFingerprint, recipientRSAPublicKey, payload, payloadType);
    }

    public EncryptResponse toEncryptResponse(SecureEnvelope envelope, String encryptedEnvelope) {
        return new EncryptResponse(envelope.getMessageId(), encryptedEnvelope, envelope.getTimestamp());
    }

    public DecryptRequest toDecryptRequest(String envelope, String recipientRSAPrivateKey, String senderPublicKey) {
        return new DecryptRequest(envelope, recipientRSAPrivateKey, senderPublicKey);
    }

    public RSAKeyParameters toRSAPublicKey(byte[] publicKeyBytes) throws Exception {
        PublicKey publicKey = RsaKeyUtils.parseRSAPublicKey(publicKeyBytes);
        return convertJavaToBCPublicKey(publicKey);
    }

    public RSAKeyParameters toRSAPrivateKey(byte[] privateKeyBytes) throws Exception {
        PrivateKey privateKey = RsaKeyUtils.parseRSAPrivateKey(privateKeyBytes);
        return convertJavaToBCPrivateKey(privateKey);
    }

    public RSAKeyParameters toRSAPublicKey(String base64) throws Exception {
        return toRSAPublicKey(fromBase64(base64));
    }

    public RSAKeyParameters toRSAPrivateKey(String base64) throws Exception {
        return toRSAPrivateKey(fromBase64(base64));
    }

    public RSAKeyParameters toRSAPublicKey(PublicKey publicKey) throws Exception {
        return convertJavaToBCPublicKey(publicKey);
    }

    public RSAKeyParameters toRSAPrivateKey(PrivateKey privateKey) throws Exception {
        return convertJavaToBCPrivateKey(privateKey);
    }

    public PublicKey toJavaPublicKey(RSAKeyParameters bcKey) throws Exception {
        java.security.KeyFactory factory = java.security.KeyFactory.getInstance("RSA");
        java.security.spec.RSAPublicKeySpec spec = new java.security.spec.RSAPublicKeySpec(bcKey.getModulus(), bcKey.getExponent());
        return factory.generatePublic(spec);
    }

    public PrivateKey toJavaPrivateKey(RSAKeyParameters bcKey) throws Exception {
        java.security.KeyFactory factory = java.security.KeyFactory.getInstance("RSA");
        java.security.spec.RSAPrivateKeySpec spec = new java.security.spec.RSAPrivateKeySpec(bcKey.getModulus(), bcKey.getExponent());
        return factory.generatePrivate(spec);
    }

    private RSAKeyParameters convertJavaToBCPublicKey(PublicKey publicKey) throws Exception {
        java.security.interfaces.RSAPublicKey rsaKey = (java.security.interfaces.RSAPublicKey) publicKey;
        return new RSAKeyParameters(false, rsaKey.getModulus(), rsaKey.getPublicExponent());
    }

    private RSAKeyParameters convertJavaToBCPrivateKey(PrivateKey privateKey) throws Exception {
        java.security.interfaces.RSAPrivateKey rsaKey = (java.security.interfaces.RSAPrivateKey) privateKey;
        return new RSAKeyParameters(true, rsaKey.getModulus(), rsaKey.getPrivateExponent());
    }

    public String toBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public String toBase64(String data) {
        return Base64.getEncoder().encodeToString(data.getBytes());
    }

    public byte[] fromBase64(String base64) {
        return Base64.getDecoder().decode(base64);
    }

    public PartnerDto toPartnerDto(Partner partner) {
        if (partner == null) return null;
        return new PartnerDto(
            partner.getId(),
            partner.getName(),
            partner.getCustomerEd25519PublicKey(),
            partner.getCustomerRsaPublicKey(),
            partner.getKeyFingerprint(),
            null, // internalKeystorePassword - never expose
            partner.getKeystorePassword() != null, // active if has keystore password
            partner.getCreatedAt() != null ? partner.getCreatedAt().toEpochMilli() : null,
            partner.getUpdatedAt() != null ? partner.getUpdatedAt().toEpochMilli() : null
        );
    }
}