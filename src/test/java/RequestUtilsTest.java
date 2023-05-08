import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

public class RequestUtilsTest {
    @Test
    @DisplayName("Teste relativo à busca do caminho absoluto de um pedido")
    public void testAbsolutePath() {
        String path = "server/files/unitTest2.txt";
        String message = "apenas um texto para ficar no ficheiro de teste";
        byte[] messageInBytes = message.getBytes();
        FileHandler.writeFile(path, messageInBytes, false);

        assertEquals(path, RequestUtils.getAbsoluteFilePath("GET : unitTest2.txt"));
    }

    @Test
    @DisplayName("Teste caso seja feito um pedido inválido")
    public void testInvalidRequest(){
        String invalidRequest = "diretorioInexistente.txt";
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            RequestUtils.getAbsoluteFilePath(invalidRequest);
        });
        assertEquals("Invalid request", exception.getMessage());
    }
}
