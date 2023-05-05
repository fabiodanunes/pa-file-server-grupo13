import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

public class MessageTest {
    @Test
    @DisplayName("Teste de getters de um objeto do tipo Message")
    public void testCreateMessageObject(){
        String message = "mensagem de teste para o teste unitário";
        byte[] messageInBytes = message.getBytes();

        BigInteger key = BigInteger.valueOf(456782765);
        byte[] keyInBytes = key.toByteArray();

        Message messageMock = new Message(messageInBytes, keyInBytes);

        assertAll(
                () -> assertEquals(message, new String(messageMock.getMessage())),
                () -> assertEquals(key, new BigInteger(messageMock.getSignature()))
        );
    }
}
