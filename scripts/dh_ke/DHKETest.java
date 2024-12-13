import java.security.KeyPairGenerator;

public class DHKETest {
    public static void main(String[] args) throws Exception {
        // Weak parameters: Small modulus size
        KeyPairGenerator keyPairGenWeak = KeyPairGenerator.getInstance("DH");
        keyPairGenWeak.initialize(1024);  // Weak prime modulus size
        keyPairGenWeak.generateKeyPair();
        System.out.println("Diffie-Hellman with weak parameters (1024-bit modulus).");

        // General Diffie-Hellman setup (quantum threat)
        KeyPairGenerator keyPairGenQuantum = KeyPairGenerator.getInstance("DH");
        keyPairGenQuantum.initialize(2048);  // Standard modulus size
        keyPairGenQuantum.generateKeyPair();
        System.out.println("Diffie-Hellman setup (quantum threat).");
    }
}
