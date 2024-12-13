import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class CBCStaticIVTest {
    public static void main(String[] args) throws Exception {
        String data = "Sensitive data";

        // AES with static IV (CBC mode)
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey aesKey = keyGen.generateKey();
        byte[] iv = new byte[16];  // Static IV (16 bytes for AES)
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        byte[] aesCiphertext = aesCipher.doFinal(data.getBytes());
        System.out.println("AES with static IV (CBC mode) encrypted data.");

        // DES with static IV (CBC mode)
        SecretKey desKey = new javax.crypto.spec.SecretKeySpec("8bytekey".getBytes(), "DES");
        byte[] desIv = new byte[8];  // Static IV (8 bytes for DES)
        IvParameterSpec desIvSpec = new IvParameterSpec(desIv);
        Cipher desCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        desCipher.init(Cipher.ENCRYPT_MODE, desKey, desIvSpec);
        byte[] desCiphertext = desCipher.doFinal(data.getBytes());
        System.out.println("DES with static IV (CBC mode) encrypted data.");
    }
}
