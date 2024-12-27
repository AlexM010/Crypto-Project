import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AES128Example {
    public static void main(String[] args) throws Exception {
        SecretKeySpec aesKey = new SecretKeySpec("1234567890abcdef".getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encrypted = cipher.doFinal("Hello World".getBytes());
        
        System.out.println("Encrypted (AES-128): " + new String(encrypted));
        //decrypt
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decrypted = cipher.doFinal(encrypted);

        System.out.println("Decrypted (AES-128): " + new String(decrypted));
    }
}
