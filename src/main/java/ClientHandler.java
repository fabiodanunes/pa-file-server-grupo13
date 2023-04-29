import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.PublicKey;

/**
 * This class represents the client handler. It handles the communication with the client. It reads the file from the
 * server and sends it to the client.
 */
public class ClientHandler extends Thread {

    private final ObjectInputStream in;
    private final ObjectOutputStream out;
    private final Socket client;
    private final Server server;
    private final PublicKey publicRSAKey;
    private final boolean isConnected;

    /**
     * Creates a ClientHandler object by specifying the socket to communicate with the client. All the processing is
     * done in a separate thread.
     *
     * @param client the socket to communicate with the client
     *
     * @throws IOException when an I/O error occurs when creating the socket
     */
    public ClientHandler ( Socket client, PublicKey publicRSAKey, Server server ) throws IOException {
        this.client = client;
        this.server = server;
        this.publicRSAKey = publicRSAKey;
        in = new ObjectInputStream ( client.getInputStream ( ) );
        out = new ObjectOutputStream ( client.getOutputStream ( ) );
        isConnected = true; // TODO: Check if this is necessary or if it should be controlled
    }

    @Override
    public void run ( ) {
        super.run ( );
        try {
            // Perform key distribution
            PublicKey senderPublicRSAKey = rsaKeyDistribution ( in );

            receiveUserInfo();

            while ( isConnected ) {
                // Reads the message to extract the path of the file
                Message message = ( Message ) in.readObject ( );
                String request = new String ( message.getMessage ( ) );
                // Reads the file and sends it to the client
                byte[] content = FileHandler.readFile ( RequestUtils.getAbsoluteFilePath ( request ) );
                sendFile ( content );
            }
            // Close connection
            closeConnection ( );
        } catch ( Exception e ) {
            // Close connection
            closeConnection ( );
        }
    }

    /**
     * Executes the key distribution protocol. The receiver will receive the public key of the sender and will send its
     * own public key.
     *
     * @param in the input stream
     *
     * @return the public key of the sender
     *
     * @throws Exception when the key distribution protocol fails
     */
    private PublicKey rsaKeyDistribution(ObjectInputStream in) throws Exception {
        // Extract the public key
        PublicKey senderPublicRSAKey = ( PublicKey ) in.readObject ( );
        // Send the public key
        sendPublicRSAKey ( );
        return senderPublicRSAKey;
    }

    /**
     * Sends the public key of the receiver to the sender.
     *
     * @throws IOException when an I/O error occurs when sending the public key
     */
    private void sendPublicRSAKey ( ) throws IOException {
        out.writeObject ( publicRSAKey );
        out.flush ( );
    }

    /**
     * Sends the file to the client
     *
     * @param content the content of the file to send
     *
     * @throws IOException when an I/O error occurs when sending the file
     */
    private void sendFile ( byte[] content ) throws IOException {
        Message response = new Message ( content );
        out.writeObject ( response );
        out.flush ( );
    }

    /**
     * Sends a message to the client
     *
     * @param content the content of the message to send
     *
     * @throws IOException when an I/O error occurs when sending the file
     */
    private void sendMessage ( String content ) throws IOException {
        Message response = new Message ( content.getBytes() );
        out.writeObject ( response );
        out.flush ( );
    }

    /**
     * Checks if the login or register information is valid, by validating the username and password given
     *
     */
    private void receiveUserInfo() throws IOException, ClassNotFoundException {
        Message message = ( Message ) in.readObject ( );
        String msg = new String ( message.getMessage ( ) );
        String[] msgSplitted = msg.split("[|]");
        String username = msgSplitted[0];
        String password = msgSplitted[1];
        if(server.getClients().contains(username)){
            String userPass = server.getPasswords().get(server.getClients().indexOf(username));
            if (password.equals(userPass)){
                sendMessage("loginSuccess");
            }
            else {
                sendMessage("loginFailed");
                receiveUserInfo();
            }
        }
        else {
            server.newClient(username, password);
            sendMessage("new");
        }

    }


    /**
     * Closes the connection by closing the socket and the streams.
     */
    private void closeConnection ( ) {
        try {
            client.close ( );
            out.close ( );
            in.close ( );
        } catch ( IOException e ) {
            throw new RuntimeException ( e );
        }
    }

}
