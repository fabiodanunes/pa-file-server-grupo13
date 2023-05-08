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
    @DisplayName("Teste de verificação de adição de um novo cliente ao Array do server")
    public void testAddClient() {
        server.newClient("joni", "987");

        assertAll(
                () -> assertNotNull(server.getClients())
        );
    }

    @Test
    @DisplayName("Teste à edição e adição de requests de um certo cliente ao ficheiro")
    public void testRequests(){
        String name = "diego";
        server.newClient(name, "123");
        server.editClientInfo(name, 2, "3");
        server.addRequest(name);

        assertEquals(4, server.getClientRequests(name));
    }

}
