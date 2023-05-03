import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Arrays;

public class Integrity {
    private static final String DIGEST_ALGORITHM = "HmacSHA256";

    /**
     * Computes the message digest of the given message.
     *
     * @param message The message to be digested.
     *
     * @return the message digest
     *
     * @throws Exception if the message digest algorithm is not available
     */
    public static byte[] generateDigest ( byte[] message, byte[] key ) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, DIGEST_ALGORITHM);
        Mac mac = Mac.getInstance(DIGEST_ALGORITHM);
        mac.init(secretKeySpec);

        return mac.doFinal(message);
    }

    /**
     * Verifies the message digest of the given message.
     *
     * @param digest         the message digest to be verified
     * @param computedDigest the computed message digest
     *
     * @return true if the message digest is valid, false otherwise
     */
    public static boolean verifyDigest ( byte[] digest , byte[] computedDigest ) {
        return Arrays.equals ( digest , computedDigest );
    }
}
