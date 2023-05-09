import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.util.Scanner;

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
        client.setUsername("joana");
        client.PrivateKeyToFile();
        client.PublicKeyToFile();
        File privateKeyFile = new File("clients/"+ client.getUsername() +"/private/"+ client.getUsername() +"PRk.key");
        File publicKeyFile = new File("pki/public_keys/"+ client.getUsername() +"PUk.key");

        assertAll(
                () -> assertTrue(privateKeyFile.exists()),
                () -> assertTrue(publicKeyFile.exists())
        );
    }

    @Test
    @DisplayName("Teste que mostra se um pedido foi escrito na pasta do utilizador")
    public void testFileToFolder() throws Exception {
        Client client = new Client("0.0.0.0", 8000);
        client.setUsername("francisco");
        String message = "pedido do francisco que vai ficar registado";
        byte[] messageInBytes = message.getBytes();
        String fileName = "UnitTest3.txt";
        String path = "clients/" +client.getUsername() +"/files/" +fileName;
        client.CopyFileToUserFolder(fileName, messageInBytes);

        assertEquals(message, new String(FileHandler.readFile(path)));
    }

    @Test
    @DisplayName("Teste de verificação para um novo utilizador")
    public void testNewUser() throws Exception {
        Client client = new Client("0.0.0.0", 8000);
        String mockUserInfo = "merces|345";
        InputStream input = new ByteArrayInputStream(mockUserInfo.getBytes());
        System.setIn(input);
        client.DHRSA();

        assertTrue(client.authenticate(new Scanner(System.in)));
    }

    @Test
    @DisplayName("Teste de verificação para quando ja existe um utilizador com aquele nome")
    public void testNewUserFail() throws Exception {
        // cliente inicial para o teste
        Client client1 = new Client("0.0.0.0", 8000);
        String mockUserInfo1 = "maurilia|909";
        InputStream input1 = new ByteArrayInputStream(mockUserInfo1.getBytes());
        System.setIn(input1);
        client1.DHRSA();
        client1.authenticate(new Scanner(System.in));

        // mesmo nome de utilizador
        Client client2 = new Client("0.0.0.0", 8000);
        String mockUserInfo2 = "maurilia|808";
        InputStream input2 = new ByteArrayInputStream(mockUserInfo2.getBytes());
        System.setIn(input2);
        client2.DHRSA();

        assertFalse(client2.authenticate(new Scanner(System.in)));
    }
}