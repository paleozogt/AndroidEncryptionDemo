package encryption;


import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;

public class KeystoreRsaEncryptor implements Encryptor {
    @Override
    public SecretKey makeKey() throws GeneralSecurityException {
        return null;
    }

    @Override
    public byte[] encrypt(byte[] plaintext) throws GeneralSecurityException,IOException {
        throw new RuntimeException("no implemented");
    }

    @Override
    public byte[] decrypt(byte[] ciphertext) throws GeneralSecurityException,IOException {
        throw new RuntimeException("no implemented");
    }
}
