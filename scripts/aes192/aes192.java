import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AES192Example {
    public static void main(String[] args) throws Exception {
        byte[] key = "123456789012345678901234".getBytes(); // AES-192 key (192 bits / 24 bytes)
        SecretKeySpec aesKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encrypted = cipher.doFinal("Hello World".getBytes());
        
        System.out.println("Encrypted (AES-192): " + new String(encrypted));
    }
}
