import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class ServerTest {
    private static Server server;

    @BeforeAll
    @DisplayName("Inicialização")
    public static void init() throws Exception {
        server = new Server(8001);
    }

    @Test
    @DisplayName("Teste de verificação de adição de um novo cliente")
    public void testAddClient() {
        server.newClient("joni", "321");

        assertAll(
                () -> assertNotNull(server.getClients()),
                () -> assertNotNull(server.getPasswords())
        );
    }

    @Test
    @DisplayName("Teste aos requests guardados no server")
    public void testRequests(){
        server.newClient("diego", "789");
        server.setRequests(server.getClients().indexOf("diego"), 3);
        server.addRequest(server.getClients().indexOf("diego"));

        assertEquals(4, server.getRequests(server.getClients().indexOf("diego")));
    }

}
