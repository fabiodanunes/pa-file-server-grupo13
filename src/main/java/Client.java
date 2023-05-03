import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

/**
 * This class represents the client. The client sends the messages to the server by means of a socket. The use of Object
 * streams enables the sender to send any kind of object.
 */
public class Client {
    private static final String HOST = "0.0.0.0";
    private final Socket client;
    private final ObjectInputStream in;
    private final ObjectOutputStream out;
    private final boolean isConnected;
    private final String userDir;
    private String Username;
    private String Password;
    private final PublicKey publicRSAKey;
    private final PrivateKey privateRSAKey;
    private PublicKey receiverPublicRSAKey;
    private BigInteger sharedSecret;

    /**
     * Constructs a Client object by specifying the port to connect to. The socket must be created before the sender can
     * send a message.
     *
     * @param port the port to connect to
     *
     * @throws IOException when an I/O error occurs when creating the socket
     */
    public Client ( int port ) throws Exception {
        client = new Socket ( HOST , port );
        out = new ObjectOutputStream ( client.getOutputStream ( ) );
        in = new ObjectInputStream ( client.getInputStream ( ) );
        isConnected = true; // TODO: Check if this is necessary or if it should be controlled
        // Create a temporary directory for putting the request files
        userDir = Files.createTempDirectory ( "fileServer" ).toFile ( ).getAbsolutePath ( );
        System.out.println ( "Temporary directory path " + userDir );
        KeyPair keyPair = Encryption.generateKeyPair ( );
        this.privateRSAKey = keyPair.getPrivate();
        this.publicRSAKey = keyPair.getPublic();
        receiverPublicRSAKey = rsaKeyDistribution();
    }

    /**
     * Gets the username of the client
     *
     *@return Username
     */
    public String getUsername() {
        return Username;
    }

    /**
     * Gets the password of the client
     *
     *@return Password
     */
    public String getPassword() {
        return Password;
    }

    /**
     * Gets the public RSA key of the client
     *
     *@return the publicRSAKey
     */
    public PublicKey getPublicRSAKey() {
        return publicRSAKey;
    }

    /**
     * Gets the private RSA key of the client
     *
     *@return the privateRSAKey
     */
    public PrivateKey getPrivateRSAKey() {
        return privateRSAKey;
    }

    /**
     * Gets the shared secret
     *
     * @return the value of the shared secret
     */
    public BigInteger getSharedSecret(){
        return sharedSecret;
    }

    /**
     * Sets the shared secret
     *
     * @param sh the value of the shared secret
     */
    public void setSharedSecret(BigInteger sh){
        this.sharedSecret = sh;
    }

    /**
     * Executes the client. It reads the file from the console and sends it to the server. It waits for the response and
     * writes the file to the temporary directory.
     */
    public void execute ( ) {
        Scanner usrInput = new Scanner ( System.in );
        try {
            DHRSA();
            while (!authenticate(usrInput));
            PrivateKeyToFile();
            PublicKeyToFile();

            while ( isConnected ) {
                // Reads the message to extract the path of the file
                System.out.println ( "Write the path of the file:" );
                String request = usrInput.nextLine ( );
                // Request the file
                sendMessage ( request );
                // Waits for the response
                processResponse ( RequestUtils.getFileNameFromRequest ( request ) );
            }
            // Close connection
            closeConnection ( );
        } catch (Exception e ) {
            throw new RuntimeException ( e );
        }
        // Close connection
        closeConnection ( );
    }

    /**
     * Asks for the credentials (Username and Password) and sends them to the server, receiving confirmation of success
     *
     * @param usrInput Scanner for the user input
     *
     * @throws IOException if an I/O error occurs when opening the socket
     * @throws ClassNotFoundException if the class of the object to be read is not found
     */
    private boolean authenticate(Scanner usrInput) throws Exception{
        String response = "";

        //Gets username and password (new or existing one)
        System.out.println("Username: ");
        String username = usrInput.nextLine();
        System.out.println("Password: ");
        String password = usrInput.nextLine();

        //Concatenates username and password in a string to be sent to the server and sends
        String msg = username + "|" + password;

        sendMessage(msg);

        //Receives the server message to check if the authentication succeeded
        response = new String(DecryptReceivedMessage());
        if(response.equals("loginFailed")){
            System.out.println("The username already exists, but the password is incorrect");
            return false;
        }
        else {
            Username = username;
            Password = password;
            System.out.println("Welcome, " + username);
            return true;
        }
    }

    /**
     * Reads the response from the server and writes the file to the temporary directory.
     *
     * @param fileName the name of the file to write
     */
    private void processResponse ( String fileName ) {
        try {
            byte[] decryptedMessage = DecryptReceivedMessage();

            System.out.println ( "File received" );
            FileHandler.writeFile ( userDir + "/" + fileName, decryptedMessage);
        } catch(Exception e){
            e.printStackTrace();
        }
    }

    public byte[] DecryptReceivedMessage() throws Exception {
        // Reads the encrypted message
        Message message = (Message) in.readObject();
        // Decrypts the received message
        byte[] decryptedMessage = Encryption.DecryptMessage(message.getMessage(), sharedSecret.toByteArray());
        // Verifies the integrity of the message
        byte[] computedDigest = Integrity.generateDigest(decryptedMessage);
        if (!Integrity.verifyDigest(message.getSignature(), computedDigest)){
            throw new RuntimeException("The message has been tampered with!");
        }

        return decryptedMessage;
    }

    /**
     * Sends a message to the server using the OutputStream of the socket. The message is sent as an object
     * of the {@link Message} class.
     *
     * @param message the message to send
     *
     * @throws IOException when an I/O error occurs when sending the message
     */
    public void sendMessage(String message) throws Exception{
        // Encrypts the message
        byte[] encryptedMessage = Encryption.EncryptMessage(message.getBytes(), sharedSecret.toByteArray());
        // Creates the MAC message object
        byte[] digest = Integrity.generateDigest(message.getBytes());
        // Creates the message object
        Message messageObj = new Message(encryptedMessage, digest);
        // Sends the message
        out.writeObject(messageObj);
        out.flush();
    }

    /**
     * Send his publicRSAKey to the server to establish a key swap to a future communication
     * */
    private void sendPublicRSAKey() throws IOException{
        out.writeObject(publicRSAKey);
        out.flush ( );
    }

    private PublicKey rsaKeyDistribution ( ) throws Exception {
        sendPublicRSAKey ( );
        return ( PublicKey ) in.readObject ( );
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

    public void DHRSA() throws Exception {
        BigInteger sharedSecret = AgreeOnSharedSecret(receiverPublicRSAKey);
        setSharedSecret(sharedSecret);
    }

    private BigInteger AgreeOnSharedSecret(PublicKey receiverPublicRSAKey) throws Exception{
        // Generates a private key
        BigInteger privateDHKey = DiffieHellman.generatePrivateKey();
        BigInteger publicDHKey = DiffieHellman.generatePublicKey(privateDHKey);
        // Sends the public key to the server encrypted
        sendPublicDHKey(Encryption.encryptRSA(publicDHKey.toByteArray(), privateRSAKey));
        // Waits for the server to send his public key
        BigInteger serverPublicKey = new BigInteger(Encryption.decryptRSA((byte[]) in.readObject(), receiverPublicRSAKey));
        // Generates the shared secret
        return DiffieHellman.computePrivateKey(serverPublicKey, privateDHKey);
    }

    private void sendPublicDHKey(byte[] publicKey) throws Exception{
        out.writeObject(publicKey);
    }

    /**
     * Save the private key generated in the file including the username + name the file
     * It is generated his own folder to save his private key
     * */
    public void PrivateKeyToFile() throws IOException {

        String caminhoAtual = new File("").getAbsolutePath();
        String NovaPasta = caminhoAtual + "/"+ getUsername() + "/private";
        File file = new File(NovaPasta);
        file.mkdirs();

        try {
            BufferedWriter writer = new BufferedWriter(new FileWriter(NovaPasta +"/"+ getUsername() +"PRk.key"));
            writer.write(getPrivateRSAKey().toString());
            writer.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Save the public key in his respective folder including the username on the filename
     * */
    public void PublicKeyToFile(){
        try {
            BufferedWriter writer = new BufferedWriter(new FileWriter("pki/public_keys/"+ getUsername() +"PUk.key"));
            writer.write(getPublicRSAKey().toString());
            writer.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
