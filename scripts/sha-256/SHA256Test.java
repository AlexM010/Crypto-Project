import java.security.MessageDigest;

public class SHA256Test {
    public static void main(String[] args) throws Exception {
        String data = "test";

        // SHA-256 Example
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] sha256Hash = sha256.digest(data.getBytes());
        System.out.println("SHA-256 hash computed.");
    }
}
