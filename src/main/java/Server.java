import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.util.ArrayList;

/**
 * This class represents a server that receives a message from the clients. The server is implemented as a thread. Each
 * time a client connects to the server, a new thread is created to handle the communication with the client.
 */
public class Server implements Runnable {
    public static final String FILE_PATH = "server/files";
    private static final String INFO_PATH = "server/Info.txt";
    private final ServerSocket server;
    private final boolean isConnected;
    private final PrivateKey privateRSAKey;
    private final PublicKey publicRSAKey;
    private static SecretKey encDecFileKey;
    private ArrayList<String> clients;


    /**
     * Constructs a Server object by specifying the port number. The server will be then created on the specified port.
     * The server will be accepting connections from all local addresses.
     *
     * @param port the port number
     *
     * @throws IOException if an I/O error occurs when opening the socket
     */
    public Server ( int port ) throws Exception {
        server = new ServerSocket ( port );
        isConnected = true;
        KeyPair keyPair = Encryption.generateKeyPair();
        this.privateRSAKey = keyPair.getPrivate();
        this.publicRSAKey = keyPair.getPublic();
        clients = new ArrayList<>();
        generateAndSaveFileKey();

    }

    /**
     * Gets the secret key of the server
     *
     * @return the secret key
     */
    public SecretKey getEncDecFileKey(){
        return encDecFileKey;
    }

    /**
     * Gets the public RSA key from the server
     *
     * @return the public RSA key
     */
    public PublicKey getPublicRSAKey() {
        return publicRSAKey;
    }

    /**
     * Gets the private RSA key from the server
     *
     * @return the private RSA key
     */
    public PrivateKey getPrivateRSAKey() {
        return privateRSAKey;
    }

    /**
     * Gets the list of clients
     *
     * @return list of clients
     */
    public ArrayList<String> getClients() {
        return clients;
    }

    public String getClientsInfoPath() {
        return INFO_PATH;
    }

    @Override
    public void run ( ) {
        try {
            sendPUkToFile();
            // Gets all clients usernames saved from file
            clientRegister();

            while ( isConnected ) {
                Socket client = server.accept ( );
                // Process the request
                process ( client );
            }
            closeConnection ( );
        } catch ( Exception e ) {
            throw new RuntimeException ( e );
        }
    }

    /**
     * Processes the request from the client.
     *
     * @throws IOException if an I/O error occurs when reading stream header
     */
    private void process ( Socket client ) throws IOException {
        ClientHandler clientHandler = new ClientHandler ( client, this );
        clientHandler.start ( );
    }


    /**
     * Generates a SecretKey using the AES algorithm
     *
     * @param n number of bits
     *
     * @return SecretKey generated with AES
     *
     * @throws NoSuchAlgorithmException when the algorithm can't be found
     */
    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        return keyGenerator.generateKey();
    }


    /**
     * Saves the SecretKey used to encrypt and decrypt the file
     * with the clients information to a file
     *
     * @throws Exception when the key file creation fails
     */
    private void generateAndSaveFileKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        File keystoreFile = new File("server/infoFileKey.jceks");

        if (!keystoreFile.exists()) {
            keystoreFile.createNewFile();
            keyStore.load(null, "pa23".toCharArray());

        } else {
            FileInputStream fis = new FileInputStream(keystoreFile);
            keyStore.load(fis, "pa23".toCharArray());
            fis.close();
        }
        if(new File(INFO_PATH).length() == 0){
            encDecFileKey = generateKey(128);

            KeyStore.SecretKeyEntry keyEntry = new KeyStore.SecretKeyEntry(encDecFileKey);

            keyStore.setEntry("encDecFileKey", keyEntry, new KeyStore.PasswordProtection("pa23".toCharArray()));

            FileOutputStream fileOutputStream = new FileOutputStream(keystoreFile);
            keyStore.store(fileOutputStream, "pa23".toCharArray());
            fileOutputStream.close();
        }
        else encDecFileKey = (SecretKey) keyStore.getKey("encDecFileKey", "pa23".toCharArray());
    }

    /**
     * Gets all the clients usernames from the Info file and stores them in the array
     */
    public void clientRegister() throws Exception {
        for (int i = 0; i < Files.lines(Path.of(INFO_PATH)).count(); i++) {
            getClients().add(FileHandler.getTextFromLine(i,0,INFO_PATH, encDecFileKey));
        }
    }

    /**
     * Adds the info of the new client to the arrays
     *
     * @param client username of the new client
     */
    public void newClient(String client, String pass) {
        getClients().add(client);
        saveClientInfo(client, pass);
    }

    /**
     * Saves the new client information in the file that contains all the clients info
     *
     * @param name username of the client to be saved in the file
     * @param pass password to be saved in the file
     */
    private void saveClientInfo(String name, String pass){
        String info = name + "/" + pass + "/" + 0;
        try {
            String encInfo = Encryption.encrypt("AES", info, encDecFileKey);
            encInfo += "\n";
            FileHandler.writeFile(getClientsInfoPath(), encInfo.getBytes(), true);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Closes the connection and the associated streams.
     */
    private void closeConnection ( ) {
        try {
            server.close ( );
        } catch ( IOException e ) {
            throw new RuntimeException ( e );
        }
    }

    /**
     * Returns the number (not index) of the line that contains the desired username, from the file that
     * contains all the clients information
     *
     * @param username username to be searched in the file
     * @return number of the line of the username passed, if it equals '0' the username doesn't exist
     */
    public int searchClientLine(String username){
        int lineNum = 0;
        try {
            for (int i = 0; i < Files.lines(Path.of(INFO_PATH)).count(); i++) {
                if (FileHandler.getTextFromLine(i, 0, INFO_PATH, encDecFileKey).equals(username)) {
                    lineNum = i + 1;
                    break;
                }
            }
        }
        catch (Exception e) {
            System.out.println("!! ERROR ACESSING FILE !!");
            e.printStackTrace();
        }
        return lineNum;
    }

    /**
     * Gets the client password from the file with all clients information
     *
     * @param username username of the client whose password shall be found
     * @return password
     */
    public String getClientPassword(String username) throws Exception {
        String pass = "";
        int line = searchClientLine(username) - 1;
        if (searchClientLine(username) == 0){
            System.out.println("Couldn't find the client username");
        }
        else {
            pass = FileHandler.getTextFromLine(line, 1, INFO_PATH, encDecFileKey);
        }
        return pass;
    }

    /**
     * Gets the client requests from the file with all clients information
     *
     * @param username username of the client whose number of requests shall be found
     * @return number of requests
     */
    public int getClientRequests(String username) throws Exception {
        int clientReq = 0;
        int line = searchClientLine(username) - 1;
        if (searchClientLine(username) == 0){
            System.out.println("Couldn't find the client username");
        }
        else {
            clientReq = Integer.parseInt(FileHandler.getTextFromLine(line, 2, INFO_PATH, encDecFileKey));
        }
        return clientReq;
    }

    /**
     * Increases the requests count of the current client
     *
     * @param username the username of the desired client
     */
    public void addRequest(String username) {
        try {
            int req = getClientRequests(username);
            req++;
            editClientInfo(username, 2,Integer.toString(req));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Changes the desired information of a certain client in the information file
     *
     * @param username username of the client
     * @param parameter position of the info to update (0 -> username, 1 -> password, 2 -> requests)
     * @param newContent info to change in the file
     */
    public void editClientInfo(String username, int parameter, String newContent) {
        int clientLine = searchClientLine(username) - 1;
        if (searchClientLine(username) == 0){
            System.out.print("Couldn't find the client username\n");
        }
        else {
            FileHandler.editTextFromLine(clientLine, parameter, newContent, INFO_PATH, encDecFileKey);
        }
    }

    /**
     * Send the server's public key to the public key folder
     */
    public void sendPUkToFile(){
        try {
            BufferedWriter writer = new BufferedWriter(new FileWriter("pki/public_keys/serverPUk.key"));
            writer.write(getPublicRSAKey().toString());
            writer.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}