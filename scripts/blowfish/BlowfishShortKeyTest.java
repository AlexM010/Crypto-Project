import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class BlowfishShortKeyTest {
    public static void main(String[] args) throws Exception {
        // Blowfish with short key (less than 128 bits)
        byte[] keyBytes = "shortkey".getBytes(); // 8 bytes (64 bits)
        SecretKey blowfishKey = new SecretKeySpec(keyBytes, "Blowfish");
        Cipher cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, blowfishKey);

        byte[] ciphertext = cipher.doFinal("Data1234".getBytes());
        System.out.println("Blowfish with short key (64 bits) encrypted data.");
    }
}
