import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class FileHandlerTest {
    @Test
    @DisplayName("teste para verificação de escrita e leitura em ficheiros")
    public void testWriteAndReaDFromFile() {
        String path = "server/files/unitTest.txt";
        String message = "mensagem de teste para os testes unitários";
        byte[] messageInBytes = message.getBytes();
        FileHandler.writeFile(path, messageInBytes, false);

        assertEquals(message, new String(FileHandler.readFile(path)));
    }
}
