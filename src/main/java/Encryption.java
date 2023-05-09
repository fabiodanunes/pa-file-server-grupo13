import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Base64;

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
     * Encrypts a message using the RSA algorithm
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
     * Decrypts a message using the RSA algorithm
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
     * Decrypts a message using the AES algorythm
     *
     * @param message   the message to be encrypted
     * @param secretKey the secret key used to decrypt the message
     *
     * @return the decrypted message as an array of bytes
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
     * Encrypts a message using the AES algorythm
     *
     * @param message   the message to be decrypted
     * @param secretKey the secret key used to encrypt the message
     *
     * @return the encrypted message as an array of bytes
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

    /**
     * Encrypts an input using any algorithm selected, and using a SecretKey
     *
     * @param algorithm algorithm to be used in encryption
     * @param input string to encrypt
     * @param key key used to encrypt
     * @return encrypted content
     *
     * @throws Exception when the encryption fails
     */
    public static String encrypt(String algorithm, String input, SecretKey key) throws Exception {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    /**
     * Decrypts an input using any algorithm selected, and using a SecretKey
     *
     * @param algorithm algorithm to be used in the decryption
     * @param cipherText encrypted text to be decrypted
     * @param key key used to decrypt
     *
     * @return decrypted test
     *
     * @throws Exception when the decryption fails
     */
    public static String decrypt(String algorithm, String cipherText, SecretKey key) throws Exception {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }
}
