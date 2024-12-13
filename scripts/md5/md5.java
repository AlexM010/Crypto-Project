import java.security.MessageDigest;

public class MD5Test {
    public static void main(String[] args) throws Exception {
        String data = "test";

        // MD5 Example
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] md5Hash = md5.digest(data.getBytes());
        System.out.println("MD5 hash computed.");
    }
}
