package encryption;

import android.security.keystore.KeyProperties;

import org.apache.commons.io.IOUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class NoKeystoreEncryptor implements Encryptor {
    SecretKey key;

    @Override
    public SecretKey makeKey() throws GeneralSecurityException,IOException {
        KeyGenerator keyGenerator= KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES);
        key= keyGenerator.generateKey();
        return key;
    }

    @Override
    public byte[] encrypt(byte[] plaintext) throws GeneralSecurityException, IOException {
        byte[] iv= genBytes(12);

        Cipher cipher= getCipher();
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        ByteArrayOutputStream byteStream= new ByteArrayOutputStream();
        DataOutputStream dataStream= new DataOutputStream(byteStream);

        dataStream.writeInt(iv.length);
        dataStream.write(iv);
        dataStream.write(cipher.doFinal(plaintext));

        return byteStream.toByteArray();
    }

    @Override
    public byte[] decrypt(byte[] ciphertext) throws GeneralSecurityException,IOException {
        ByteArrayInputStream byteStream= new ByteArrayInputStream(ciphertext);
        DataInputStream dataStream= new DataInputStream(byteStream);
        byte[] iv= new byte[dataStream.readInt()];
        dataStream.read(iv);

        Cipher cipher= getCipher();
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        CipherInputStream cipherStream= new CipherInputStream(byteStream, cipher);

        ByteArrayOutputStream outputStream= new ByteArrayOutputStream();
        IOUtils.copy(cipherStream, outputStream);
        return outputStream.toByteArray();
    }

    protected String getCipherTransformation() {
        return KeyProperties.KEY_ALGORITHM_AES + '/' + KeyProperties.BLOCK_MODE_GCM + '/' + KeyProperties.ENCRYPTION_PADDING_NONE;
    }

    protected Cipher getCipher() throws NoSuchAlgorithmException, NoSuchPaddingException {
        return Cipher.getInstance(getCipherTransformation());
    }

    protected byte[] genBytes(int len) throws NoSuchAlgorithmException {
        byte[] bytes= new byte[len];
        SecureRandom.getInstance("SHA1PRNG").nextBytes(bytes);
        return bytes;
    }
}
