import java.io.Serializable;

/**
 * This class represents a message object that is sent to the server by the client.
 */
public class Message implements Serializable {
    private final byte[] message;
    private final byte[] signature;

    /**
     * Constructs a Message object by specifying the message bytes that will be sent to the server.
     *
     * @param message the message that is sent to the server
     */
    public Message(byte[] message, byte[] signature){
        this.message = message;
        this.signature = signature;
    }

    /**
     * Gets the message string.
     *
     * @return the message string
     */
    public byte[] getMessage() {
        return message;
    }

    /**
     * Gets the signature string.
     *
     * @return the message string
     */
    public byte[] getSignature() {
        return signature;
    }
}