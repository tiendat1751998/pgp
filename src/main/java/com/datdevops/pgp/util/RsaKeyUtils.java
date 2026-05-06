package com.datdevops.pgp.util;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;

import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

public class RsaKeyUtils {

    public static final String ALGORITHM = "RSA";
    public static final String TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    public static byte[] generateRSAPublicKeyX509(PublicKey publicKey) {
        return publicKey.getEncoded();
    }

    public static byte[] generateRSAPrivateKeyPKCS8(PrivateKey privateKey) {
        return privateKey.getEncoded();
    }

    public static PublicKey parseRSAPublicKey(byte[] x509Encoded) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(x509Encoded);
        PublicKey key = factory.generatePublic(keySpec);
        if (!(key instanceof RSAPublicKey)) {
            throw new IllegalArgumentException("Decoded key is not an RSA public key");
        }
        return key;
    }

    public static PrivateKey parseRSAPrivateKey(byte[] pkcs8Encoded) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8Encoded);
        PrivateKey key = factory.generatePrivate(keySpec);
        if (!(key instanceof RSAPrivateKey)) {
            throw new IllegalArgumentException("Decoded key is not an RSA private key");
        }
        return key;
    }

    public static RSAPublicKeySpec extractRSAPublicKeySpec(PublicKey publicKey) {
        if (!(publicKey instanceof RSAPublicKey)) {
            throw new IllegalArgumentException("Key is not an RSA public key: " + publicKey.getClass().getName());
        }
        RSAPublicKey rsaKey = (RSAPublicKey) publicKey;
        return new RSAPublicKeySpec(rsaKey.getModulus(), rsaKey.getPublicExponent());
    }

    public static RSAPrivateKeySpec extractRSAPrivateKeySpec(PrivateKey privateKey) {
        if (!(privateKey instanceof RSAPrivateKey)) {
            throw new IllegalArgumentException("Key is not an RSA private key: " + privateKey.getClass().getName());
        }
        RSAPrivateKey rsaKey = (RSAPrivateKey) privateKey;
        return new RSAPrivateKeySpec(rsaKey.getModulus(), rsaKey.getPrivateExponent());
    }

    public static byte[] encrypt(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    public static String toBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] fromBase64(String base64) {
        return Base64.getDecoder().decode(base64);
    }
}