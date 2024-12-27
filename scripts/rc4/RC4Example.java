import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class RC4Example {
    public static void main(String[] args) throws Exception {
        byte[] key = "12345678".getBytes();  // Key for RC4
        SecretKeySpec rc4Key = new SecretKeySpec(key, "RC4");
        
        Cipher cipher = Cipher.getInstance("RC4");
        cipher.init(Cipher.ENCRYPT_MODE, rc4Key);
        byte[] encrypted = cipher.doFinal("Hello World".getBytes());
        
        System.out.println("Ciphertext (RC4): " + new String(encrypted));

        cipher.init(Cipher.DECRYPT_MODE, rc4Key);
        byte[] decrypted = cipher.doFinal(encrypted);
        System.out.println("Decrypted: " + new String(decrypted));
    }
}
