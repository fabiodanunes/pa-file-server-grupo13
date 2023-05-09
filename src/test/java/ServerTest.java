import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import static org.junit.jupiter.api.Assertions.*;

public class ServerTest {
    private static Server server;

    @BeforeAll
    @DisplayName("Inicialização")
    public static void init() throws Exception {
        server = new Server(8001);
    }

    @Test
    @DisplayName("Teste para quando o servidor não encontra o username introduzido")
    public void testWrongPasswordAndRequests(){
        String name = "Osvaldo";
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        System.setOut(new PrintStream(outputStream));
        server.editClientInfo(name, 0, "0");

        assertAll(
                () -> assertEquals("Couldn't find the client username\n", outputStream.toString()),
                () -> assertEquals("", server.getClientPassword(name)),
                () -> assertEquals(0, server.getClientRequests(name))
        );
    }
}
