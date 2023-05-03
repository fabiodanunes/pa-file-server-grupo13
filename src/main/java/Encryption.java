import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class Encryption {
    /**
     * Generates the private and public keys using the RSA algorithm
     *
     * @return both keys
     *
     * @throws Exception when the algorithm isn't supported or when a parameter is invalid
     */
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);

        return generator.generateKeyPair();
    }

    /**
     * encrypts a message using the RSA algorithm
     *
     * @param message message to be encrypted
     * @param publicKey the key used in the encryption
     *
     * @return the encrypted message
     *
     * @throws Exception when something goes wrong with the encryption
     */
    public static byte[] encryptRSA(byte[] message, Key publicKey) throws Exception{
        Cipher cipher = Cipher.getInstance ( "RSA" );
        cipher.init ( Cipher.ENCRYPT_MODE , publicKey );

        return cipher.doFinal ( message );
    }

    /**
     * decrypts a message using the RSA algorithm
     *
     * @param message message to be decrypted
     * @param privateKey the key used in the decryption
     *
     * @return the decrypted message
     *
     * @throws Exception when something goes wrong with the decryption
     */
    public static byte[] decryptRSA ( byte[] message , Key privateKey ) throws Exception {
        Cipher cipher = Cipher.getInstance ( "RSA" );
        cipher.init ( Cipher.DECRYPT_MODE , privateKey );

        return cipher.doFinal ( message );
    }

    /**
     * @param message   the message to be encrypted
     * @param secretKey the secret key used to encrypt the message
     *
     * @return the encrypted message as an array of bytes
     *
     * @throws Exception when the decryption fails
     */
    public static byte[] DecryptMessage(byte[] message, byte[] secretKey) throws Exception{
        byte[] secretKeyPadded = ByteBuffer.allocate(32).put(secretKey).array();
        SecretKeySpec secreteKeySpec = new SecretKeySpec(secretKeyPadded, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secreteKeySpec);

        return cipher.doFinal(message);
    }

    /**
     * @param message   the message to be decrypted
     * @param secretKey the secret key used to decrypt the message
     *
     * @return the decrypted message as an array of bytes
     *
     * @throws Exception when the encryption fails
     */
    public static byte[] EncryptMessage(byte[]message, byte[] secretKey) throws Exception{
        byte[] secretKeyPadded = ByteBuffer.allocate(32).put(secretKey).array();
        SecretKeySpec secreteKeySpec = new SecretKeySpec(secretKeyPadded, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secreteKeySpec);

        return cipher.doFinal(message);
    }
}
