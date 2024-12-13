import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AES128Example {
    public static void main(String[] args) throws Exception {
        byte[] key = "1234567890abcdef".getBytes(); // AES-128 key (128 bits / 16 bytes)
        SecretKeySpec aesKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encrypted = cipher.doFinal("Hello World".getBytes());
        
        System.out.println("Encrypted (AES-128): " + new String(encrypted));
    }
}
