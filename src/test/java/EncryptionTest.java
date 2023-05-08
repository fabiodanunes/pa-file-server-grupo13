import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

public class EncryptionTest {
    @Test
    @DisplayName("Teste que verifica se uma mensagem foi encriptada e desencriptada corretamente")
    public void testEncryptDecrypt() throws Exception {
        String message = "mensagem de teste";
        byte[] messageInBytes = message.getBytes();
        BigInteger secretKey = BigInteger.valueOf(625477622);
        byte[] secretKeyInBytes = secretKey.toByteArray();
        byte[] encryptedMessage = Encryption.EncryptMessage(messageInBytes, secretKeyInBytes);
        byte[] decryptedMessage = Encryption.DecryptMessage(encryptedMessage, secretKeyInBytes);

        assertEquals(message, new String(decryptedMessage));
    }
}
