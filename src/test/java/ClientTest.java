import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.*;

class ClientTest {
    @BeforeAll
    @DisplayName("inicialização do servidor")
    public static void init() throws Exception {
        MainServer.main(new String[]{});
    }

    @Test
    @DisplayName("teste da atribuição do username e password do client")
    public void testUsernameAndPassowrd() throws Exception {
        Client client = new Client("0.0.0.0", 8000);
        client.setUsername("fabio");
        client.setPassword("123");

        assertAll(
                () -> assertEquals("fabio", client.getUsername()),
                () -> assertEquals("123", client.getPassword())
        );
    }

    @Test
    @DisplayName("teste que verifica que as chaves criadas não são nulas")
    public void testKeys() throws Exception {
        Client client = new Client("0.0.0.0", 8000);
        client.DHRSA();

        assertAll(
                () -> assertNotNull(client.getPublicRSAKey()),
                () -> assertNotNull(client.getPrivateRSAKey()),
                () -> assertNotNull(client.getSharedSecret())
        );
    }

    @Test
    @DisplayName("Teste que verifica a criação de ficheiros ao se conectar um novo cliente")
    public void testKeysToFiles() throws Exception {
        Client client = new Client("0.0.0.0", 8000);
        client.setUsername("John Doe");
        client.PrivateKeyToFile();
        client.PublicKeyToFile();
        File privateKeyFile = new File("clients/"+ client.getUsername() +"/private/"+ client.getUsername() +"PRk.key");
        File publicKeyFile = new File("pki/public_keys/"+ client.getUsername() +"PUk.key");

        assertAll(
                () -> assertTrue(privateKeyFile.exists()),
                () -> assertTrue(publicKeyFile.exists())
        );
    }
}