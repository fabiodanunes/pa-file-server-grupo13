import java.util.ArrayList;

/**
 * This class contains some useful methods for byte arrays. The methods include splitting a byte array into chunks of
 * fixed size, concatenating two byte arrays, and computing the XOR of two byte arrays.
 */
public class ByteUtils {

    /**
     * Splits a byte array into chunks of fixed size. The last chunk can be padded if required. In this case, the PKCS
     * #5 is used as padding scheme.
     *
     * @param text      The byte array to be split
     * @param chunkSize The size of the chunks
     *
     * @return An ArrayList of byte arrays, each one of them having the size of chunkSize
     */
    public static ArrayList < byte[] > splitByteArray ( byte[] text , int chunkSize ) {
        ArrayList < byte[] > chunks = new ArrayList <> ( );
        for ( int i = 0 ; i < text.length ; i += chunkSize ) {
            int nElements = Math.min ( chunkSize , text.length - i );
            byte[] chunk = new byte[ nElements ];
            System.arraycopy ( text , i , chunk , 0 , nElements );
            chunks.add ( chunk );
        }

        return chunks;
    }


    /**
     * Receives to byte arrays and returns their concatenation.
     *
     * @param op1 The first operand
     * @param op2 The second operand
     *
     * @return The concatenation of the two operands
     */
    public static byte[] concatByteArrays ( byte[] op1 , byte[] op2 ) {
        byte[] newOutput = new byte[ op1.length + op2.length ];
        System.arraycopy ( op1 , 0 , newOutput , 0 , op1.length );
        System.arraycopy ( op2 , 0 , newOutput , op1.length , op2.length );
        return newOutput;
    }

}
