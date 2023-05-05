import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.*;

public class ByteUtilsTest {
    @Test
    @DisplayName("Teste à separação de uma mensagem muito grande")
    public void testBigMessage(){
        String message = "mensagem muito grande com o objetivo de a separar em chunks e depois voltar a juntá-los de " +
                "forma a realizar este teste. Só para garantir vou aumentar esta mensagem mais um pouco";
        byte[] messageInBytes = message.getBytes();
        ArrayList< byte[] > chunks = ByteUtils.splitByteArray(messageInBytes, 16);


        assertTrue(chunks.size() > 1);
    }

    @Test
    @DisplayName("Teste à concatenação de duas mensagens")
    public void testJoinMessages(){
        String message1 = "Olá.";
        byte[] message1InBytes = message1.getBytes();
        String message2 = " Tudo bem?";
        byte[] message2InBytes = message2.getBytes();
        byte[] joinedMessage = ByteUtils.concatByteArrays(message1InBytes, message2InBytes);

        assertEquals("Olá. Tudo bem?", new String(joinedMessage));
    }
}
