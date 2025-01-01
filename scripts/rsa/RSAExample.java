import java.security.*;
import javax.crypto.Cipher;

public class RSAExample {
    public static void main(String[] args) throws Exception {
        String message = "Test RSA Encryption";
        byte[] messageBytes = message.getBytes();

        // RSA-512
        System.out.println("Testing RSA-512...");
        KeyPairGenerator keyGen512 = KeyPairGenerator.getInstance("RSA");
        keyGen512.initialize(512);
        KeyPair keyPair512 = keyGen512.generateKeyPair();
        Cipher cipher512 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher512.init(Cipher.ENCRYPT_MODE, keyPair512.getPublic());
        byte[] encrypted512 = cipher512.doFinal(messageBytes);
        System.out.println("RSA-512 Encrypted: " + new String(encrypted512));

        // RSA-2048
        System.out.println("\nTesting RSA-2048...");
        KeyPairGenerator keyGen2048 = KeyPairGenerator.getInstance("RSA");
        keyGen2048.initialize(2048);
        KeyPair keyPair2048 = keyGen2048.generateKeyPair();
        Cipher cipher2048 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher2048.init(Cipher.ENCRYPT_MODE, keyPair2048.getPublic());
        byte[] encrypted2048 = cipher2048.doFinal(messageBytes);
        System.out.println("RSA-2048 Encrypted: " + new String(encrypted2048));

        // RSA No Padding
        System.out.println("\nTesting RSA No Padding...");
        KeyPairGenerator keyGenNoPadding = KeyPairGenerator.getInstance("RSA");
        keyGenNoPadding.initialize(2048);
        KeyPair keyPairNoPadding = keyGenNoPadding.generateKeyPair();
        Cipher cipherNoPadding = Cipher.getInstance("RSA/ECB/NoPadding");
        cipherNoPadding.init(Cipher.ENCRYPT_MODE, keyPairNoPadding.getPublic());
        byte[] encryptedNoPadding = cipherNoPadding.doFinal(messageBytes);
        System.out.println("RSA No Padding Encrypted: " + new String(encryptedNoPadding));
    }
}
