public class MainClient {

    public static void main ( String[] args ) throws Exception {
        Client client = new Client ( "0.0.0.0", 8000 );
        client.execute ( );
    }
}
