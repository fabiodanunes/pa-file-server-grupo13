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
    public Client ( String host, int port ) throws Exception {
        client = new Socket ( host , port );
        out = new ObjectOutputStream ( client.getOutputStream ( ) );
        in = new ObjectInputStream ( client.getInputStream ( ) );
        isConnected = true;
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
     * Sets the username of the client
     *
     * @param username the username of the client
     */
    public void setUsername(String username) {
        this.Username = username;
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
     * Sets the password of the client
     *
     * @param password the password of the client
     */
    public void setPassword(String password){
        this.Password = password;
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
            while (!authenticate(usrInput));
            PrivateKeyToFile();
            PublicKeyToFile();

            while ( isConnected ) {
                String response = new String(DecryptReceivedMessage());
                if (response.equals("newHandshake")){
                    System.out.println("***Executing new handshake***");
                    receiverPublicRSAKey = rsaKeyDistribution();
                    DHRSA();
                    PrivateKeyToFile();
                    PublicKeyToFile();
                }
                // Reads the message to extract the path of the file
                System.out.println("Write the path of the file:");
                String request = usrInput.nextLine();
                // Request the file
                sendMessage(request);
                // Waits for the response
                processResponse(RequestUtils.getFileNameFromRequest(request));

                byte[] msg = FileHandler.readFile(userDir + "/" + RequestUtils.getFileNameFromRequest ( request ));
                CopyFileToUserFolder(RequestUtils.getFileNameFromRequest ( request ), msg);
            }
            // Close connection
            closeConnection ( );
        }
        catch (IllegalArgumentException e){
            System.out.println("The request is invalid! Make sure the format used is correct -> GET : file_name.txt" );
        }
        catch (Exception e ) {
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
    public boolean authenticate(Scanner usrInput) throws Exception{
        String response;
        String userInfo = "";
        String[] userInfoSeparated;

        System.out.println("Username/Password (Separated by \"|\" please): ");
        userInfo = usrInput.nextLine();
        if(!userInfo.contains("|")) return false;
        userInfoSeparated = userInfo.split("[|]");
        if(userInfoSeparated.length < 2 || userInfoSeparated[0].equals("") || userInfoSeparated[1].equals("")) return false;

        DHRSA();

        sendMessage(userInfo);

        //Receives the server message to check if the authentication succeeded
        response = new String(DecryptReceivedMessage());
        if(response.equals("loginFailed")){
            System.out.println("The username already exists, but the password is incorrect");
        }
        else {
            setUsername(userInfoSeparated[0]);
            setPassword(userInfoSeparated[1]);
            if (response.equals("loginSuccess")){
                System.out.println("Welcome back, " + getUsername());
            }
            else {
                System.out.println("Welcome, " + getUsername());
            }
            return true;
        }
        return false;
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
            System.out.println ( );
            System.out.println ( "File content: " );
            System.out.println ( new String(decryptedMessage));
            System.out.println ( );
            FileHandler.writeFile ( userDir + "/" + fileName, decryptedMessage, false);
        } catch(Exception e){
            e.printStackTrace();
        }
    }

    /**
     * Decrypts the message sent by the server
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
        byte[] decrypted = Encryption.DecryptMessage(message.getMessage(), getSharedSecret().toByteArray());
        if(new String(decrypted).equals("Ficheiro leitura")){
            return receiveFile();
        }
        // Verifies the integrity of the message
        byte[] computedDigest = Integrity.generateDigest(decrypted, getSharedSecret().toByteArray());
        if (!Integrity.verifyDigest(message.getSignature(), computedDigest)){
            throw new RuntimeException("The message has been tampered with!");
        }
        return decrypted;
    }

    /**
     * Method to read each message sent by the server containing the file content requested
     *
     * @return finalResult of concatenation all messages received with all parts of file content requested
     *
     * */

    public byte[] receiveFile () throws Exception {
        byte[] finalResult = new byte[0];
        while (true) {
            Message message = (Message) in.readObject();
            byte[] decrypted = Encryption.DecryptMessage(message.getMessage(), sharedSecret.toByteArray());
            if (new String(decrypted).equals("Termina ficheiro")) {
                return finalResult;
            }

            // Verifies the integrity of the message
            byte[] computedDigest = Integrity.generateDigest(decrypted, getSharedSecret().toByteArray());
            if (!Integrity.verifyDigest(message.getSignature(), computedDigest)){
                throw new RuntimeException("The message has been tampered with!");
            }

            finalResult = ByteUtils.concatByteArrays(finalResult, decrypted);
        }
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
        byte[] encryptedMessage = Encryption.EncryptMessage(message.getBytes(), getSharedSecret().toByteArray());
        // Creates the MAC message object
        byte[] digest = Integrity.generateDigest(message.getBytes(), getSharedSecret().toByteArray());
        // Creates the message object
        Message messageObj = new Message(encryptedMessage, digest);
        // Sends the message
        out.writeObject(messageObj);
        out.flush();
    }

    /**
     * Send his publicRSAKey to the server to establish a key swap to a future communication
     *
     * @throws IOException when an I/O error occurs when sending the message
     * */
    private void sendPublicRSAKey() throws IOException{
        out.writeObject(publicRSAKey);
        out.flush ( );
    }

    /**
     * Executes the key distribution protocol. The client sends its public key to the server and receives the public
     * key of the server.
     *
     * @return the public key of the client
     *
     * @throws Exception when the key distribution protocol fails
     */
    public PublicKey rsaKeyDistribution ( ) throws Exception {
        sendPublicRSAKey ( );
        return ( PublicKey ) in.readObject ( );
    }

    /**
     * Closes the connection by closing the socket and the streams.
     */
    public void closeConnection ( ) {
        try {
            client.close ( );
            out.close ( );
            in.close ( );
        } catch ( IOException e ) {
            throw new RuntimeException ( e );
        }
    }

    /**
     * Performs the Diffie-Hellman algorithm to secure a shared secret key to secure communication between the client
     * and the server
     *
     * @throws Exception in case the AgreeOnSharedSecret() method throws an excpetion
     */
    public void DHRSA() throws Exception {
        BigInteger sharedSecret = AgreeOnSharedSecret(receiverPublicRSAKey);
        setSharedSecret(sharedSecret);
    }

    /**
     * Performs the Diffie-Hellman algorithm to agree on a shared private key.
     *
     * @param receiverPublicRSAKey the public key of the server
     *
     * @return the shared private key
     *
     * @throws Exception when the Diffie-Hellman algorithm fails
     */
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

    /**
     * Sends the public key to the server.
     *
     * @param publicKey the public key to send
     *
     * @throws Exception when the public key cannot be sent
     */
    private void sendPublicDHKey(byte[] publicKey) throws Exception{
        out.writeObject(publicKey);
    }

    /**
     * Save the private key generated in the file including the username + name the file
     * It is generated his own folder to save his private key
     * */
    public void PrivateKeyToFile(){

        String caminhoAtual = new File("").getAbsolutePath();
        String NovaPasta = caminhoAtual + "/clients/"+ getUsername() + "/private";
        File file = new File(NovaPasta);
        file.mkdirs();

            try {
                BufferedWriter writer = new BufferedWriter(new FileWriter(NovaPasta + "/" + getUsername() + "PRk.key"));
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
            BufferedWriter writer = new BufferedWriter(new FileWriter("pki/public_keys/" + getUsername() + "PUk.key"));
            writer.write(getPublicRSAKey().toString());
            writer.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Method that writes in the clients folder the file requested
     *
     * @param Filename filename requested
     * @param text content of file requested
     *
     * */
    public void CopyFileToUserFolder (String Filename,byte[] text){
        String caminhoAtual = new File("").getAbsolutePath();
        String NovaPasta = caminhoAtual + "/clients/" + getUsername() + "/files";
        File file = new File(NovaPasta);
        file.mkdirs();

        try {
            BufferedWriter writer = new BufferedWriter(new FileWriter(NovaPasta + "/" + Filename));
            writer.write(new String(text));
            writer.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
