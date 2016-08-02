package encryption;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public interface Encryptor {
    SecretKey makeKey() throws GeneralSecurityException;
    byte[] encrypt(byte[] plaintext) throws GeneralSecurityException,IOException;
    byte[] decrypt(byte[] ciphertext) throws GeneralSecurityException,IOException;
}
