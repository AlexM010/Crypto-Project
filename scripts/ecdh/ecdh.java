import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyAgreement;
import java.security.spec.ECGenParameterSpec;

public class ECDHTest {
    public static void main(String[] args) throws Exception {
        // Generate key pair for ECDH
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1")); // NIST P-256 curve
        KeyPair keyPair1 = kpg.generateKeyPair();
        KeyPair keyPair2 = kpg.generateKeyPair();

        // Perform ECDH key agreement
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(keyPair1.getPrivate());
        ka.doPhase(keyPair2.getPublic(), true);
        byte[] sharedSecret = ka.generateSecret();
        System.out.println("ECDH shared secret: " + sharedSecret.length + " bytes");
    }
}
