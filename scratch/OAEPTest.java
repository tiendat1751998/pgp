import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.Arrays;

public class OAEPTest {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        Cipher jceCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        jceCipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
        
        byte[] sessionKey = new byte[32];
        new SecureRandom().nextBytes(sessionKey);
        
        byte[] encrypted = jceCipher.doFinal(sessionKey);
        
        // Convert private key
        java.security.interfaces.RSAPrivateCrtKey priv = (java.security.interfaces.RSAPrivateCrtKey) kp.getPrivate();
        RSAPrivateCrtKeyParameters bcPriv = new RSAPrivateCrtKeyParameters(
            priv.getModulus(),
            priv.getPublicExponent(),
            priv.getPrivateExponent(),
            priv.getPrimeP(),
            priv.getPrimeQ(),
            priv.getPrimeExponentP(),
            priv.getPrimeExponentQ(),
            priv.getCrtCoefficient()
        );
        
        // Try BC decrypt with SHA256 / SHA1
        OAEPEncoding bcCipher1 = new OAEPEncoding(new RSAEngine(), new SHA256Digest(), new SHA1Digest(), null);
        bcCipher1.init(false, bcPriv);
        
        try {
            byte[] decrypted1 = bcCipher1.processBlock(encrypted, 0, encrypted.length);
            System.out.println("BC decrypted with SHA-256 / SHA-1: " + Arrays.equals(sessionKey, decrypted1));
        } catch (Exception e) {
            System.out.println("Failed SHA-256 / SHA-1: " + e.getMessage());
        }

        // Try BC decrypt with SHA256 / SHA256
        OAEPEncoding bcCipher2 = new OAEPEncoding(new RSAEngine(), new SHA256Digest(), new SHA256Digest(), null);
        bcCipher2.init(false, bcPriv);
        
        try {
            byte[] decrypted2 = bcCipher2.processBlock(encrypted, 0, encrypted.length);
            System.out.println("BC decrypted with SHA-256 / SHA-256: " + Arrays.equals(sessionKey, decrypted2));
        } catch (Exception e) {
            System.out.println("Failed SHA-256 / SHA-256: " + e.getMessage());
        }
    }
}
