import java.security.*;

public class RSAExample {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        
        keyPairGen.initialize(512);  // RSA 512-bit
        KeyPair keyPair_512 = keyPairGen.generateKeyPair();
        System.out.println("RSA 512-bit key generated.");

        keyPairGen.initialize(1024);  // RSA 1024-bit
        KeyPair keyPair_1024 = keyPairGen.generateKeyPair();
        System.out.println("RSA 1024-bit key generated.");
    }
}
