import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public class DiffieHellman {
    private static final BigInteger G = BigInteger.valueOf ( 3 );
    private static final BigInteger N = BigInteger.valueOf ( 1289971646 );
    private static final int NUM_BITS = 128;

    /**
     * Generates the DH private key
     *
     * @return the DH private key
     *
     * @throws NoSuchAlgorithmException when a particular cryptographic algorithm is requested but is not available in
     * the environment
     */
    public static BigInteger generatePrivateKey ( ) throws NoSuchAlgorithmException {
        Random randomGenerator = SecureRandom.getInstance ( "SHA1PRNG" );

        return new BigInteger ( NUM_BITS , randomGenerator );
    }

    /**
     * Generates the DH public from the private key
     *
     * @param privateKey the DH private key
     *
     * @return the DH public key
     */
    public static BigInteger generatePublicKey ( BigInteger privateKey ) {
        return G.modPow ( privateKey , N );
    }

    /**
     * Generates the shared secret between the two ends
     *
     * @param publicKey the DH public key from one side of the communication channel
     * @param privateKey the DH private key from the other side of the communication channel
     *
     * @return the shared secret
     */
    public static BigInteger computePrivateKey ( BigInteger publicKey , BigInteger privateKey ) {
        return publicKey.modPow ( privateKey , N );
    }
}
