package com.paleozogt.encryptor;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyProperties;

import org.apache.commons.io.IOUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
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
import javax.crypto.spec.SecretKeySpec;

/**
 * Encrypts/decrypts with symmetric secret key (AES).
 *
 * Since there's no keystore, we have no choice but to store
 * the secret key to disk.  Data encryption/decryption
 * happens in the main OS.
 */
public class NoKeystoreEncryptor implements Encryptor {
    Context ctx;
    final String WRAPPED_SECRET_KEY_FILENAME= getClass().getSimpleName();

    public static boolean isSupported() { return true; }

    public NoKeystoreEncryptor(Context ctx) {
        this.ctx= ctx;
    }

    @Override
    public SecretKey makeKey() throws GeneralSecurityException,IOException {
        // TODO: why doesn't lint "TrulyRandom" catch this line?
        KeyGenerator keyGenerator= KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES);
        SecretKey key= keyGenerator.generateKey();
        saveSecretKey(key);
        return key;
    }

    @Override
    public byte[] encrypt(byte[] plaintext) throws GeneralSecurityException, IOException {
        byte[] iv= genBytes(12);

        Cipher cipher= getCipher();
        cipher.init(Cipher.ENCRYPT_MODE, loadSecretKey(), new IvParameterSpec(iv));

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
        cipher.init(Cipher.DECRYPT_MODE, loadSecretKey(), new IvParameterSpec(iv));
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

    protected void saveSecretKey(SecretKey key) throws IOException {
        DataOutputStream stream= null;
        try {
            stream= new DataOutputStream(new FileOutputStream(new File(ctx.getFilesDir(), WRAPPED_SECRET_KEY_FILENAME)));
            byte[] keyBytes= key.getEncoded();
            stream.writeInt(keyBytes.length);
            stream.write(keyBytes);
        } finally {
            IOUtils.closeQuietly(stream);
        }
    }

    SecretKey loadSecretKey() throws IOException {
        DataInputStream stream= null;
        try {
            stream= new DataInputStream(new FileInputStream(new File(ctx.getFilesDir(), WRAPPED_SECRET_KEY_FILENAME)));
            byte[] keyBytes= new byte[stream.readInt()];
            stream.read(keyBytes);
            return new SecretKeySpec(keyBytes, 0, keyBytes.length, KeyProperties.KEY_ALGORITHM_AES);
        } finally {
            IOUtils.closeQuietly(stream);
        }
    }
}
