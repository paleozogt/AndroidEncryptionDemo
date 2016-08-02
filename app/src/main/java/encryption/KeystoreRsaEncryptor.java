package encryption;


import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Calendar;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.security.auth.x500.X500Principal;

/**
 * Encrypts/decrypts with symmetric secret key (AES).
 *
 * The secret key is wrapped (encrypted) with an asymmetric (RSA) key
 * that is stored in (and encrypted/decrypted by) the Android KeyStore.
 *
 * While the wrapping/unwrapping happens in the Android Keystore
 * (which may be backed by secure hardware) data encryption/decryption
 * happens in the main OS.
 *
 * The wrapped key is stored on disk.
 */
@TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
public class KeystoreRsaEncryptor implements Encryptor {
    Logger logger= LoggerFactory.getLogger(getClass());
    Context ctx;

    final String KEY_ALIAS= getClass().getSimpleName();
    final String PROVIDER= "AndroidKeyStore";
    final String WRAPPED_SECRET_KEY_FILENAME= getClass().getSimpleName();

    public KeystoreRsaEncryptor(Context ctx) {
        this.ctx= ctx;
    }

    @Override
    public SecretKey makeKey() throws GeneralSecurityException,IOException {
        logger.debug("making key pair");
        KeyPair keyPair= makeKeyPair();
        logger.debug("making secret key");
        SecretKey key= makeSecretKey();
        logger.debug("wrapping secret key");
        saveWrappedKey(wrapSecretKey(key));
        return key;
    }

    @Override
    public byte[] encrypt(byte[] plaintext) throws GeneralSecurityException,IOException {
        SecretKey key= unwrapSecretKey(loadWrappedKey());
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
        SecretKey key= unwrapSecretKey(loadWrappedKey());
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

    protected KeyPair makeKeyPair() throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, PROVIDER);
        KeyPairGeneratorSpec.Builder builder= new KeyPairGeneratorSpec.Builder(ctx)
                .setAlias(KEY_ALIAS)
                .setStartDate(getCertStartDate())
                .setEndDate(getCertEndDate())
                .setSubject(new X500Principal("CN=Sensory"))
                .setSerialNumber(BigInteger.ONE);
        kpg.initialize(builder.build());

        KeyPair keyPair = kpg.generateKeyPair();

        try {
            KeyFactory factory = KeyFactory.getInstance(keyPair.getPrivate().getAlgorithm(), PROVIDER);
            KeyInfo keyInfo= (KeyInfo)factory.getKeySpec(keyPair.getPrivate(), KeyInfo.class);
            logger.debug("KeyInfo {}", keyInfo);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                logger.debug("isInsideSecureHardware: {}", keyInfo.isInsideSecureHardware());
            }
        } catch (Exception e) {
            logger.debug("Can't make KeyFactory ({})", e.getMessage());
        }

        return keyPair;
    }

    protected SecretKey makeSecretKey() throws GeneralSecurityException {
        KeyGenerator keyGenerator= KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES);
        return keyGenerator.generateKey();
    }

    protected void saveWrappedKey(byte[] wrappedKey) throws IOException {
        DataOutputStream stream= null;
        try {
            stream= new DataOutputStream(new FileOutputStream(new File(ctx.getFilesDir(), WRAPPED_SECRET_KEY_FILENAME)));
            stream.writeInt(wrappedKey.length);
            stream.write(wrappedKey);
        } finally {
            IOUtils.closeQuietly(stream);
        }
    }

    byte[] loadWrappedKey() throws IOException {
        DataInputStream stream= null;
        try {
            stream= new DataInputStream(new FileInputStream(new File(ctx.getFilesDir(), WRAPPED_SECRET_KEY_FILENAME)));
            byte[] wrappedKey= new byte[stream.readInt()];
            stream.read(wrappedKey);
            return wrappedKey;
        } finally {
            IOUtils.closeQuietly(stream);
        }
    }

    protected byte[] wrapSecretKey(SecretKey key) throws GeneralSecurityException,IOException {
        KeyStore keyStore= KeyStore.getInstance(PROVIDER);
        keyStore.load(null);
        KeyStore.PrivateKeyEntry keyEntry= (KeyStore.PrivateKeyEntry)keyStore.getEntry(KEY_ALIAS, null);

        Cipher cipher= Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.WRAP_MODE, keyEntry.getCertificate().getPublicKey());
        return cipher.wrap(key);
    }

    protected SecretKey unwrapSecretKey(byte[] bytes) throws GeneralSecurityException,IOException {
        KeyStore keyStore= KeyStore.getInstance(PROVIDER);
        keyStore.load(null);
        KeyStore.PrivateKeyEntry keyEntry= (KeyStore.PrivateKeyEntry)keyStore.getEntry(KEY_ALIAS, null);

        Cipher cipher= Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.UNWRAP_MODE, keyEntry.getPrivateKey());
        return (SecretKey)cipher.unwrap(bytes, KeyProperties.KEY_ALGORITHM_AES, Cipher.SECRET_KEY);
    }

    protected String getCipherTransformation() {
        return KeyProperties.KEY_ALGORITHM_AES + '/' + KeyProperties.BLOCK_MODE_GCM + '/' + KeyProperties.ENCRYPTION_PADDING_NONE;
    }

    protected Cipher getCipher() throws NoSuchAlgorithmException, NoSuchPaddingException {
        return Cipher.getInstance(getCipherTransformation());
    }

    protected Date getCertStartDate() {
        return Calendar.getInstance().getTime();
    }

    protected Date getCertEndDate() {
        Calendar calendar= Calendar.getInstance();
        calendar.add(Calendar.YEAR, 100);
        return calendar.getTime();
    }

    protected byte[] genBytes(int len) throws NoSuchAlgorithmException {
        byte[] bytes= new byte[len];
        SecureRandom.getInstance("SHA1PRNG").nextBytes(bytes);
        return bytes;
    }
}
