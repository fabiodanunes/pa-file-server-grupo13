import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;

/**
 * This class represents a server that receives a message from the clients. The server is implemented as a thread. Each
 * time a client connects to the server, a new thread is created to handle the communication with the client.
 */
public class Server implements Runnable {
    public static final String FILE_PATH = "server/files";
    private static final String INFO_PATH = "clients/Info.txt";
    private final ServerSocket server;
    private final boolean isConnected;
    private final PrivateKey privateRSAKey;
    private final PublicKey publicRSAKey;
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
     * Gets all the clients usernames from the Info file and stores them in the array
     */
    public void clientRegister() throws IOException {
        for (int i = 0; i < Files.lines(Path.of(INFO_PATH)).count(); i++) {
            clients.add(FileHandler.getTextFromLine(i,0,INFO_PATH));
        }
    }

    /**
     * Adds the info of the new client to the arrays
     *
     * @param client username of the new client
     */
    public void newClient(String client, String pass) {
        clients.add(client);
        saveClientInfo(client, pass);
    }

    /**
     * Saves the new client information in the file that contains all the clients info
     *
     * @param name username of the client to be saved in the file
     * @param pass password to be saved in the file
     */
    private void saveClientInfo(String name, String pass){
        //TODO : Encrypt file with this info
        String info = name + "|" + pass + "|" + 0 + "\n";
        FileHandler.writeFile(getClientsInfoPath(), info.getBytes(), true);
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
                if (FileHandler.getTextFromLine(i, 0, INFO_PATH).equals(username)) {
                    lineNum = i + 1;
                    break;
                }
            }
        }
        catch (IOException e){
            System.out.println("!! ERROR OPENING FILE !!");
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
    public String getClientPassword(String username) {
        String pass = "";
        int line = searchClientLine(username) - 1;
        if (searchClientLine(username) == 0){
            System.out.println("Couldn't find the client username");
        }
        else {
            pass = FileHandler.getTextFromLine(line, 1, INFO_PATH);
        }
        return pass;
    }

    /**
     * Gets the client requests from the file with all clients information
     *
     * @param username username of the client whose number of requests shall be found
     * @return number of requests
     */
    public int getClientRequests(String username) {
        String clientReq = "";
        int line = searchClientLine(username) - 1;
        if (searchClientLine(username) == 0){
            System.out.println("Couldn't find the client username");
        }
        else {
            clientReq = FileHandler.getTextFromLine(line, 2, INFO_PATH);
        }
        return Integer.parseInt(clientReq);
    }

    /**
     * Increases the requests count of the current client
     *
     */
    public void addRequest(String username) {
        int req = getClientRequests(username);
        req++;
        editClientInfo(username, 2,Integer.toString(req));
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
            System.out.println("Couldn't find the client username");
        }
        else {
            FileHandler.editTextFromLine(clientLine, parameter, newContent, INFO_PATH);
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