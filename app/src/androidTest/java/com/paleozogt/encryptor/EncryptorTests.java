package com.paleozogt.encryptor;

import android.content.Context;
import android.support.test.InstrumentationRegistry;

import junit.framework.Assert;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

@RunWith(Parameterized.class)
public class EncryptorTests {
    @Parameterized.Parameters
    public static Iterable<Object[]> data() {
        return Arrays.asList(new Object[][]{
                { NoKeystoreEncryptor.class },
                { KeystoreRsaEncryptor.class },
                { KeystoreAesEncryptor.class }
        });
    }

    Class<? extends Encryptor> clazz;
    Encryptor encryptor;

    public EncryptorTests(Class<? extends Encryptor> clazz) {
        this.clazz= clazz;
    }

    @Before
    public void setup() throws InstantiationException, IllegalAccessException, InvocationTargetException {
        try {
            encryptor= clazz.getDeclaredConstructor(Context.class).newInstance(InstrumentationRegistry.getTargetContext());
        } catch (NoSuchMethodException e) {
            encryptor= clazz.newInstance();
        }
    }

    byte[] makePlainText(int numBytes) throws UnsupportedEncodingException {
        return StringUtils.repeat('A', numBytes).getBytes("UTF-8");
    }

    @Test
    public void roundtrip() throws GeneralSecurityException, IOException {
        encryptor.makeKey();
        byte[] plaintext= makePlainText(1024);
        byte[] ciphertext= encryptor.encrypt(plaintext);
        byte[] roundtriptext= encryptor.decrypt(ciphertext);
        Assert.assertTrue(ArrayUtils.isEquals(plaintext, roundtriptext));
    }
}
