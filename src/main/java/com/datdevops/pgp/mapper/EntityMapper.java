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
import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Map;

@Component
public class EntityMapper {

    public EntityMapper() {
        // Removed improper manual instantiation of CryptoConfig
    }

    public EncryptResponse toEncryptResponse(SecureEnvelope envelope, String encryptedEnvelope) {
        return new EncryptResponse(envelope.getMessageId(), encryptedEnvelope, envelope.getTimestamp());
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
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec spec = new RSAPublicKeySpec(bcKey.getModulus(), bcKey.getExponent());
        return factory.generatePublic(spec);
    }

    public PrivateKey toJavaPrivateKey(RSAKeyParameters bcKey) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec spec = new RSAPrivateKeySpec(bcKey.getModulus(), bcKey.getExponent());
        return factory.generatePrivate(spec);
    }

    private RSAKeyParameters convertJavaToBCPublicKey(PublicKey publicKey) throws Exception {
        if (!(publicKey instanceof java.security.interfaces.RSAPublicKey)) {
            throw new IllegalArgumentException("Key is not an RSA public key: " + publicKey.getClass().getName());
        }
        java.security.interfaces.RSAPublicKey rsaKey = (java.security.interfaces.RSAPublicKey) publicKey;
        return new RSAKeyParameters(false, rsaKey.getModulus(), rsaKey.getPublicExponent());
    }

    private RSAKeyParameters convertJavaToBCPrivateKey(PrivateKey privateKey) throws Exception {
        if (!(privateKey instanceof java.security.interfaces.RSAPrivateKey)) {
            throw new IllegalArgumentException("Key is not an RSA private key: " + privateKey.getClass().getName());
        }
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
        if (partner == null)
            return null;
        return new PartnerDto(
                partner.getId(),
                partner.getName(),
                partner.getCustomerEd25519PublicKey(),
                partner.getCustomerRsaPublicKey(),
                partner.getKeyFingerprint(),
                partner.getKeystorePassword() != null,
                partner.getCreatedAt() != null ? partner.getCreatedAt().toEpochMilli() : null,
                partner.getUpdatedAt() != null ? partner.getUpdatedAt().toEpochMilli() : null);
    }
}