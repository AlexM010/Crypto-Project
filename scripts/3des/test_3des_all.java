/*
  test_3des_all.java
  Demonstrates single-key, two-key, and three-key 3DES usage in one file.
  Each uses a literal key in SecretKeySpec(...) plus cipher.init(...).

  Compile:
    javac test_3des_all.java
  Run:
    java test_3des_all
*/

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class test_3des_all {
    public static void main(String[] args) throws Exception {
        testSingleKey3DES();
        testTwoKey3DES();
        testThreeKey3DES();
    }

    private static void testSingleKey3DES() throws Exception {
        System.out.println("=== 3DES Single-Key (1-key) ===");
        // Single key repeated: "ABCDEFGHABCDEFGHABCDEFGH"
        Cipher cipherEnc = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipherEnc.init(Cipher.ENCRYPT_MODE,
            new SecretKeySpec("ABCDEFGHABCDEFGHABCDEFGH".getBytes("UTF-8"), "DESede"));

        byte[] plaintext = "SingleKey3DES!".getBytes();
        byte[] ciphertext = cipherEnc.doFinal(plaintext);
        System.out.println("Ciphertext length (1-key): " + ciphertext.length);

        Cipher cipherDec = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipherDec.init(Cipher.DECRYPT_MODE,
            new SecretKeySpec("ABCDEFGHABCDEFGHABCDEFGH".getBytes("UTF-8"), "DESede"));
        byte[] decrypted = cipherDec.doFinal(ciphertext);
        System.out.println("Decrypted (1-key): " + new String(decrypted, "UTF-8") + "\n");
    }

    private static void testTwoKey3DES() throws Exception {
        System.out.println("=== 3DES Two-Key (2-key) ===");
        // 16-byte key => "ABCDEFGHIJKLMNOP"
        Cipher cipherEnc = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipherEnc.init(Cipher.ENCRYPT_MODE,
            new SecretKeySpec("ABCDEFGHIJKLMNOPABCDEFGH".getBytes("UTF-8"), "DESede"));

        byte[] plaintext = "TwoKey3DESExample".getBytes("UTF-8");
        byte[] ciphertext = cipherEnc.doFinal(plaintext);
        System.out.println("Ciphertext length (2-key): " + ciphertext.length);

        Cipher cipherDec = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipherDec.init(Cipher.DECRYPT_MODE,
            new SecretKeySpec("ABCDEFGHIJKLMNOPABCDEFGH".getBytes("UTF-8"), "DESede"));
        byte[] decrypted = cipherDec.doFinal(ciphertext);
        System.out.println("Decrypted (2-key): " + new String(decrypted, "UTF-8") + "\n");
    }

    private static void testThreeKey3DES() throws Exception {
        System.out.println("=== 3DES Three-Key (3-key) ===");
        // 24-byte key => "ABCDEFGH12345678XYZ#12!@"
        Cipher cipherEnc = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipherEnc.init(Cipher.ENCRYPT_MODE,
            new SecretKeySpec("ABCDEFGH12345678XYZ#12!@".getBytes("UTF-8"), "DESede"));

        byte[] plaintext = "ThreeKey3DES!!!".getBytes("UTF-8");
        byte[] ciphertext = cipherEnc.doFinal(plaintext);
        System.out.println("Ciphertext length (3-key): " + ciphertext.length);

        Cipher cipherDec = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipherDec.init(Cipher.DECRYPT_MODE,
            new SecretKeySpec("ABCDEFGH12345678XYZ#12!@".getBytes("UTF-8"), "DESede"));
        byte[] decrypted = cipherDec.doFinal(ciphertext);
        System.out.println("Decrypted (3-key): " + new String(decrypted, "UTF-8") + "\n");
    }
}
