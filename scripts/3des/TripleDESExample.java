import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class TripleDESExample {
    public static void main(String[] args) throws Exception {
        byte[] key1 = "12345678".getBytes();
        byte[] key2 = "87654321".getBytes();
        byte[] key3 = "abcdef01".getBytes();
        
        // 3DES with 1 key
        SecretKeySpec desKey = new SecretKeySpec(key1, "DES");
        Cipher cipher1 = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher1.init(Cipher.ENCRYPT_MODE, desKey);
        byte[] encrypted1 = cipher1.doFinal("Hello World".getBytes());
        
        // 3DES with 2 keys (using key1 and key2)
        SecretKeySpec desKey2 = new SecretKeySpec(key1, "DES");
        Cipher cipher2 = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher2.init(Cipher.ENCRYPT_MODE, desKey2);
        byte[] encrypted2 = cipher2.doFinal("Hello World".getBytes());
        
        // 3DES with 3 keys
        SecretKeySpec desKey3 = new SecretKeySpec(key3, "DES");
        Cipher cipher3 = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher3.init(Cipher.ENCRYPT_MODE, desKey3);
        byte[] encrypted3 = cipher3.doFinal("Hello World".getBytes());
        
        System.out.println("Encrypted data (3DES with 1 key): " + new String(encrypted1));
        System.out.println("Encrypted data (3DES with 2 keys): " + new String(encrypted2));
        System.out.println("Encrypted data (3DES with 3 keys): " + new String(encrypted3));
    }
}
