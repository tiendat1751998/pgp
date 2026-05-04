package com.datdevops.pgp.service;

import com.datdevops.pgp.util.RsaKeyUtils;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

@Service
public class RSAKeyPairGeneratorService {

    private static final int KEY_SIZE = 4096;
    private static final BigInteger PUBLIC_EXPONENT = BigInteger.valueOf(65537);
    private static final int CERTAINTY = 80;

    private final SecureRandom secureRandom;

    public RSAKeyPairGeneratorService() {
        this.secureRandom = new SecureRandom();
    }

    public AsymmetricCipherKeyPair generateRSAKeyPair() {
        RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
        generator.init(new RSAKeyGenerationParameters(PUBLIC_EXPONENT, secureRandom, KEY_SIZE, CERTAINTY));
        return generator.generateKeyPair();
    }

    public RSAKeyParameters getPublicKey(AsymmetricCipherKeyPair keyPair) {
        return (RSAKeyParameters) keyPair.getPublic();
    }

    public RSAKeyParameters getPrivateKey(AsymmetricCipherKeyPair keyPair) {
        return (RSAKeyParameters) keyPair.getPrivate();
    }

    public byte[] getModulus(AsymmetricCipherKeyPair keyPair) {
        return getPublicKey(keyPair).getModulus().toByteArray();
    }

    public byte[] getEncodedPublicKey(AsymmetricCipherKeyPair keyPair) throws Exception {
        RSAKeyParameters pubKey = getPublicKey(keyPair);
        return convertBCToJavaPublicKey(pubKey).getEncoded();
    }

    public byte[] getEncodedPrivateKey(AsymmetricCipherKeyPair keyPair) throws Exception {
        RSAKeyParameters privKey = getPrivateKey(keyPair);
        RSAKeyParameters pubKey = getPublicKey(keyPair);
        return convertBCToJavaPrivateKey(privKey, pubKey).getEncoded();
    }

    public String getBase64PublicKey(AsymmetricCipherKeyPair keyPair) throws Exception {
        return RsaKeyUtils.toBase64(getEncodedPublicKey(keyPair));
    }

    public String getBase64PrivateKey(AsymmetricCipherKeyPair keyPair) throws Exception {
        return RsaKeyUtils.toBase64(getEncodedPrivateKey(keyPair));
    }

    public PublicKey parsePublicKey(byte[] x509Encoded) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        java.security.spec.X509EncodedKeySpec keySpec = new java.security.spec.X509EncodedKeySpec(x509Encoded);
        return factory.generatePublic(keySpec);
    }

    public PrivateKey parsePrivateKey(byte[] pkcs8Encoded) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        java.security.spec.PKCS8EncodedKeySpec keySpec = new java.security.spec.PKCS8EncodedKeySpec(pkcs8Encoded);
        return factory.generatePrivate(keySpec);
    }

    public PublicKey parsePublicKey(String base64) throws Exception {
        return parsePublicKey(RsaKeyUtils.fromBase64(base64));
    }

    public PrivateKey parsePrivateKey(String base64) throws Exception {
        return parsePrivateKey(RsaKeyUtils.fromBase64(base64));
    }

    private PublicKey convertBCToJavaPublicKey(RSAKeyParameters bcKey) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec spec = new RSAPublicKeySpec(bcKey.getModulus(), bcKey.getExponent());
        return factory.generatePublic(spec);
    }

    private PrivateKey convertBCToJavaPrivateKey(RSAKeyParameters bcPrivateKey, RSAKeyParameters bcPublicKey) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec spec = new RSAPrivateKeySpec(bcPrivateKey.getModulus(), bcPrivateKey.getExponent());
        return factory.generatePrivate(spec);
    }
}