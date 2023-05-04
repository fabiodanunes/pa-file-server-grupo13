import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
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
    private BigInteger sharedSecret;
    private int clientInd;
    private String clientUsername;

    /**
     * Creates a ClientHandler object by specifying the socket to communicate with the client. All the processing is
     * done in a separate thread.
     *
     * @param client the socket to communicate with the client
     *
     * @throws IOException when an I/O error occurs when creating the socket
     */
    public ClientHandler ( Socket client, Server server ) throws IOException {
        this.client = client;
        this.server = server;
        this.publicRSAKey = server.getPublicRSAKey();
        in = new ObjectInputStream ( client.getInputStream ( ) );
        out = new ObjectOutputStream ( client.getOutputStream ( ) );
        isConnected = true; // TODO: Check if this is necessary or if it should be controlled
    }

    /**
     * Gets the shared secret
     *
     * @return the value of the shared secret
     */
    public BigInteger getSharedSecret() {
        return sharedSecret;
    }

    /**
     * Sets the shared secret
     *
     * @param sh the value of the shared secret
     */
    public void setSharedSecret(BigInteger sh) {
        this.sharedSecret = sh;
    }

    @Override
    public void run ( ) {
        super.run ( );
        try {
            DHRSA();
            receiveUserInfo();

            while ( isConnected ) {
                if (server.getRequests(clientInd) >= 5){
                    System.out.println("!!5 Requests made!!\n!!For safety reasons, executing a new handshake!!");
                    sendMessage("newHandshake");
                    DHRSA();
                    server.setRequests(clientInd, 0);
                }
                else {
                    sendMessage("continue");
                }
                byte[] decryptedMessage = DecryptReceivedMessage();
                String request = new String(decryptedMessage);

                // Reads the file and sends it to the client
                byte[] content = FileHandler.readFile(RequestUtils.getAbsoluteFilePath(request));
                sendFile(content);
                server.addRequest(clientInd);
            }

            // Close connection
            closeConnection ( );
        } catch (Exception e ) {
            // Close connection
            closeConnection ( );
        }
        removeClientKeys();
    }

    /**
     * Sends the public key of the receiver to the sender
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
    private void sendFile(byte[] content) throws Exception{
        // Encrypts the message
        byte[] encryptedContent = Encryption.EncryptMessage(content, getSharedSecret().toByteArray());
        // Creates the MAC message object
        byte[] digest = Integrity.generateDigest(content);
        // Creates the message object
        Message messageObj = new Message(encryptedContent, digest);
        // Sends the message
        out.writeObject(messageObj);
        out.flush();
    }

    /**
     * Sends a message to the client
     *
     * @param content the content of the message to send
     *
     * @throws IOException when an I/O error occurs when sending the file
     */
    private void sendMessage(String content) throws Exception{
        // Encrypts the message
        byte[] encryptedContent = Encryption.EncryptMessage(content.getBytes(), getSharedSecret().toByteArray());
        // Creates the MAC message object
        byte[] digest = Integrity.generateDigest(content.getBytes());
        // Creates the message object
        Message messageObj = new Message(encryptedContent, digest);
        // Sends the message
        out.writeObject(messageObj);
        out.flush();
    }

    /**
     * Checks if the login or register information is valid, by validating the username and password given
     */
    private void receiveUserInfo() throws Exception {
        String msg = new String(DecryptReceivedMessage());
        String[] msgSplitted = msg.split("[|]");
        String username = msgSplitted[0];
        String password = msgSplitted[1];
        if(server.getClients().contains(username)){
            int userIndex = server.getClients().indexOf(username);
            String userPass = server.getPasswords().get(userIndex);
            if (password.equals(userPass)){
                sendMessage("loginSuccess");
                clientInd = userIndex;
            }
            else {
                sendMessage("loginFailed");
                receiveUserInfo();
            }
        }
        else {
            server.newClient(username, password);
            sendMessage("new");
            clientInd = server.getClients().indexOf(username);
        }
        clientUsername = username;
    }

    /**
     * Decrypts the message sent by the client
     *
     * @return the decrypted message in bytes
     *
     * @throws Exception when an I/O errors occurs or when an end of file or end of stream is reached unexpectedly
     * during input
     */
    public byte[] DecryptReceivedMessage() throws Exception {
        // Reads the encrypted message
        Message message = (Message) in.readObject();
        // Decrypts the received message
        byte[] decryptedMessage = Encryption.DecryptMessage(message.getMessage(), getSharedSecret().toByteArray());
        // Verifies the integrity of the message
        byte[] computedDigest = Integrity.generateDigest(decryptedMessage);
        if (!Integrity.verifyDigest(message.getSignature(), computedDigest)){
            throw new RuntimeException("The message has been tampered with!");
        }

        return decryptedMessage;
    }

    /**
     * Closes the connection by closing the socket and the streams
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

    /**
     * receives the RSA public key from the client and Performs the Diffie-Hellman algorithm to secure a shared secret
     * key to secure communication between the client and the server
     *
     * @throws Exception in case the AgreeOnSharedSecret() method throws an excpetion
     */
    public void DHRSA() throws Exception {
        // Perform key distribution
        PublicKey senderPublicRSAKey = rsaKeyDistribution(in);
        // Agree on a shared secret
        BigInteger sharedSecret = AgreeOnSharedSecret(senderPublicRSAKey);
        setSharedSecret(sharedSecret);
    }

    /**
     * Executes the key distribution protocol. The server will receive the public key of the client and will send its
     * own public key
     *
     * @param in the input stream
     *
     * @return the public key of the client
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
     * Performs the Diffie-Hellman algorithm to agree on a shared private key
     *
     * @param senderPublicRSAKey the public key of the client
     *
     * @return the shared secret key
     *
     * @throws Exception when the key agreement protocol fails
     */
    private BigInteger AgreeOnSharedSecret(PublicKey senderPublicRSAKey) throws Exception {
        // Generate a pair of keys
        BigInteger privateKey = DiffieHellman.generatePrivateKey();
        BigInteger publicKey = DiffieHellman.generatePublicKey(privateKey);
        // Extracts the public key from the request
        BigInteger clientPublicKey = new BigInteger(Encryption.decryptRSA((byte[]) in.readObject(), senderPublicRSAKey));
        // Send the public key to the client
        sendPublicDHKey(publicKey);
        // Generates the shared secret
        return DiffieHellman.computePrivateKey(clientPublicKey, privateKey);
    }


    /**
     * Sends the public key to the client
     *
     * @param publicKey the public key to be sent
     *
     * @throws Exception when the public key cannot be sent
     */
    private void sendPublicDHKey(BigInteger publicKey) throws Exception {
        out.writeObject(Encryption.encryptRSA(publicKey.toByteArray(), server.getPrivateRSAKey()));
    }


    /**
     * Removes all files and directories used to store the client's public and private
     * keys information
     */
    private void removeClientKeys(){
        String currentPath = new File("").getAbsolutePath();
        File clientDirectory = new File(currentPath + "/clients/"+ clientUsername);
        File clientPUkey = new File(currentPath + "/pki/public_keys/"+ clientUsername + "PUk.key");
        deleteDirectory(clientDirectory);
        clientPUkey.delete();
        System.out.println(clientUsername + "'s keys info removed");
    }


    /**
     * Deletes the directory and all its files
     *
     * @param directoryToBeDeleted the directory to be deleted
     */
    private void deleteDirectory(File directoryToBeDeleted) {
        File[] allContents = directoryToBeDeleted.listFiles();
        if (allContents != null) {
            for (File file : allContents) {
                deleteDirectory(file);
            }
        }
        directoryToBeDeleted.delete();
    }
}
