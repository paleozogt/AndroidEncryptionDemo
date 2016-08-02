package com.paleozogt.encryptor;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;

public interface Encryptor {
    SecretKey makeKey() throws GeneralSecurityException,IOException;
    byte[] encrypt(byte[] plaintext) throws GeneralSecurityException,IOException;
    byte[] decrypt(byte[] ciphertext) throws GeneralSecurityException,IOException;
}
