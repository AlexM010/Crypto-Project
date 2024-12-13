import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ECBModeTest {
    public static void main(String[] args) throws Exception {
        // AES with ECB mode
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey aesKey = keyGen.generateKey();
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] aesCiphertext = aesCipher.doFinal("SensitiveData".getBytes());
        System.out.println("AES in ECB mode encrypted data.");

        // DES with ECB mode
        SecretKey desKey = new SecretKeySpec("8bytekey".getBytes(), "DES");
        Cipher desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        desCipher.init(Cipher.ENCRYPT_MODE, desKey);
        byte[] desCiphertext = desCipher.doFinal("Data1234".getBytes());
        System.out.println("DES in ECB mode encrypted data.");
    }
}
