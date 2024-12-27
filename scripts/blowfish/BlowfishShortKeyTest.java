import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class BlowfishShortKeyTest {
    public static void main(String[] args) throws Exception {
        // Blowfish with short key (less than 128 bits)
        byte[] keyBytes = "shortkey".getBytes(); // 8 bytes (64 bits)
        SecretKey blowfishKey = new SecretKeySpec("shortkey".getBytes(), "Blowfish");
        Cipher cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, blowfishKey);

        byte[] ciphertext = cipher.doFinal("Data1234".getBytes());
        System.out.println("Ciphertext: " + new String(ciphertext));

        cipher.init(Cipher.DECRYPT_MODE, blowfishKey);
        byte[] plaintext = cipher.doFinal(ciphertext);
        System.out.println("Decrypted: " + new String(plaintext));

    }
}
