package com.paleozogt.encryptor;

import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Encrypts/decrypts with symmetric secret key (AES).
 *
 * The secret key is stored in (and encrypted/decrypted by) the Android KeyStore
 * (which may be backed by secure hardware).
 */
@TargetApi(Build.VERSION_CODES.M)
public class KeystoreAesEncryptor implements Encryptor {
    Logger logger= LoggerFactory.getLogger(getClass());
    final String KEY_ALIAS= getClass().getSimpleName();
    final String PROVIDER= "AndroidKeyStore";

    public static boolean isSupported() { return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M; }

    @Override
    @SuppressLint("TrulyRandom")    // since this is an Android M+ class, the TrulyRandom warning doesn't apply
    public SecretKey makeKey() throws GeneralSecurityException,IOException {
        KeyGenerator keyGenerator  = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER);
        keyGenerator.init(
                new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .build()
        );
        SecretKey key = keyGenerator.generateKey();

        SecretKeyFactory factory = SecretKeyFactory.getInstance(key.getAlgorithm(), PROVIDER);
        KeyInfo keyInfo= (KeyInfo)factory.getKeySpec(key, KeyInfo.class);
        logger.debug("isInsideSecureHardware: {}", keyInfo.isInsideSecureHardware());

        return key;
    }

    @Override
    public byte[] encrypt(byte[] plaintext) throws GeneralSecurityException,IOException {
        KeyStore keyStore= KeyStore.getInstance(PROVIDER);
        keyStore.load(null);
        KeyStore.SecretKeyEntry keyEntry= (KeyStore.SecretKeyEntry)keyStore.getEntry(KEY_ALIAS, null);

        Cipher cipher= getCipher();
        cipher.init(Cipher.ENCRYPT_MODE, keyEntry.getSecretKey());
        GCMParameterSpec params= cipher.getParameters().getParameterSpec(GCMParameterSpec.class);

        ByteArrayOutputStream byteStream= new ByteArrayOutputStream();
        DataOutputStream dataStream= new DataOutputStream(byteStream);

        dataStream.writeInt(params.getTLen());
        byte[] iv= params.getIV();
        dataStream.writeInt(iv.length);
        dataStream.write(iv);

        dataStream.write(cipher.doFinal(plaintext));

        return byteStream.toByteArray();
    }

    @Override
    public byte[] decrypt(byte[] ciphertext) throws GeneralSecurityException,IOException {
        KeyStore keyStore= KeyStore.getInstance(PROVIDER);
        keyStore.load(null);
        KeyStore.SecretKeyEntry keyEntry= (KeyStore.SecretKeyEntry)keyStore.getEntry(KEY_ALIAS, null);

        ByteArrayInputStream byteStream= new ByteArrayInputStream(ciphertext);
        DataInputStream dataStream= new DataInputStream(byteStream);
        int tlen= dataStream.readInt();
        byte[] iv= new byte[dataStream.readInt()];
        dataStream.read(iv);

        Cipher cipher= getCipher();
        cipher.init(Cipher.DECRYPT_MODE, keyEntry.getSecretKey(), new GCMParameterSpec(tlen, iv));
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
}
