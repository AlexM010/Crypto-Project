import java.security.MessageDigest;

public class SHA1Test {
    public static void main(String[] args) throws Exception {
        String data = "test";

        // SHA-1 Example
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(data.getBytes());
        System.out.println("SHA-1 hash computed.");
    }
}
