import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class DESExample {
    public static void main(String[] args) throws Exception {
        byte[] keyBytes = "12345678".getBytes();  // 56 bits key for DES
        SecretKey key = new SecretKeySpec(keyBytes, "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal("Hello World".getBytes());

        System.out.println("Encrypted data: " + new String(encrypted));
    }
}
