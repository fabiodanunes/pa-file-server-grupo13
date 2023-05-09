import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

public class FileHandlerTest {
    private static Server server;

    @BeforeAll
    @DisplayName("Inicialização")
    public static void init() throws Exception {
        server = new Server(8008);
    }

    @Test
    @DisplayName("teste para verificação de escrita e leitura em ficheiros")
    public void testWriteAndReaDFromFile() {
        String path = "server/files/unitTest.txt";
        String message = "mensagem de teste para os testes unitários";
        byte[] messageInBytes = message.getBytes();
        FileHandler.writeFile(path, messageInBytes, false);

        assertEquals(message, new String(FileHandler.readFile(path)));
    }

    @Test
    @DisplayName("teste para verificação de edição em ficheiros")
    public void testEditFile() throws Exception {
        String path = "server/files/unitTest3.txt";
        String message = "oliver/456/2";
        String encryptedMessage = Encryption.encrypt("AES", message, server.getEncDecFileKey());
        FileHandler.writeFile(path, encryptedMessage.getBytes(), false);
        // o teste mudará o nome para "osvaldo"
        FileHandler.editTextFromLine(0, 0, "osvaldo", path, server.getEncDecFileKey());

        assertEquals("osvaldo/456/2", FileHandler.getLineFromFile(0, path, server.getEncDecFileKey()));
    }

    @Test
    @DisplayName("teste para verificação de remoção de um ficheiro")
    public void testDeleteFile(){
        File file = new File("server/files/TOBEDELETED");
        file.mkdir();
        String message = "bla bla bla conteúdo que será eliminado";
        FileHandler.writeFile(file.getPath() +"/unitTest4.txt", message.getBytes(), false);
        FileHandler.deleteDirectory(new File(file.getPath()));

        assertFalse(new File(file.getPath() +"/unitTest4.txt").exists());
    }
}
