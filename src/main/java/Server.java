import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
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
    private final ServerSocket server;
    private final boolean isConnected;
    private final PrivateKey privateRSAKey;
    private final PublicKey publicRSAKey;
    private final int MAX_CLIENTS = 10;
    private ArrayList<String> clients;
    private ArrayList<String> passwords;
    private int[] requests;


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
        isConnected = true; // TODO: Check if this is necessary or if it should be controlled
        KeyPair keyPair = Encryption.generateKeyPair();
        this.privateRSAKey = keyPair.getPrivate();
        this.publicRSAKey = keyPair.getPublic();
        clients = new ArrayList<>();
        passwords = new ArrayList<>();
        requests = new int[MAX_CLIENTS];
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

    /**
     * Gets the list of passwords from the clients
     *
     * @return the list of passwords
     */
    public ArrayList<String> getPasswords() {
        return passwords;
    }

    public int getRequests(int ind) {
        return requests[ind];
    }

    public void addRequest(int ind){
        requests[ind]++;
    }

    public void setRequests(int ind, int n){
        requests[ind] = n;
    }

    @Override
    public void run ( ) {
        try {
            sendPUkToFile();

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
     * Adds the info of the new client to the arrays
     *
     * @param client username of the new client
     * @param password password of the new client
     */
    public void newClient(String client, String password) {
        clients.add(client);
        passwords.add(password);
        requests[clients.indexOf(client)] = 0;
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