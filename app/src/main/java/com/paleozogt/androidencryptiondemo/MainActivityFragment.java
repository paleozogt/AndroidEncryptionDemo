package com.paleozogt.androidencryptiondemo;

import android.os.Bundle;
import android.os.Environment;
import android.support.v4.app.Fragment;
import android.support.v7.app.AlertDialog;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.EditText;
import android.widget.Spinner;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.paleozogt.encryptor.Encryptor;
import com.paleozogt.encryptor.KeystoreAesEncryptor;
import com.paleozogt.encryptor.KeystoreRsaEncryptor;
import com.paleozogt.encryptor.NoKeystoreEncryptor;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public class MainActivityFragment extends Fragment {
    Logger logger= LoggerFactory.getLogger(getClass());
    Encryptor encryptor;
    byte[] plaintext;
    byte[] ciphertext;
    byte[] roundtriptext;

    public MainActivityFragment() {
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        View view= inflater.inflate(R.layout.fragment_main, container, false);

        view.findViewById(R.id.gen_key).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                genKey();
            }
        });

        view.findViewById(R.id.gen_plaintext).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                genPlaintext();
            }
        });

        view.findViewById(R.id.encrypt).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                encrypt();
            }
        });

        view.findViewById(R.id.decrypt).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                decrypt();
            }
        });

        Spinner encryptImplSpinner= (Spinner)view.findViewById(R.id.encrypt_impl_spinner);
        final String[] encryptImpls= getResources().getStringArray(R.array.encrypt_impls);
        encryptImplSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                encryptor= makeEncryptor(encryptImpls[position]);
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {

            }
        });
        logger.debug("encryption impls: {}", (Object)encryptImpls);
        encryptor= makeEncryptor(encryptImpls[0]);

        return view;
    }

    @Override
    public void onResume() {
        super.onResume();
        genPlaintext();
    }

    protected Encryptor makeEncryptor(String id) {
        if (id.equals(getString(R.string.encrypt_androidkeystore_aes))) {
            return new KeystoreAesEncryptor();
        } else if (id.equals(getString(R.string.encrypt_androidkeystore_rsa))) {
            return new KeystoreRsaEncryptor(getActivity());
        } else if (id.equals(getString(R.string.encrypt_nokeystore))) {
            return new NoKeystoreEncryptor(getActivity());
        } else {
            throw new IllegalArgumentException("no such encryptor " + id);
        }
    }

    protected void genKey() {
        try {
            logger.debug("genKey");
            encryptor.makeKey();
            logger.debug("genKey done");
        } catch (Exception e) {
            showExceptionDialog(e);
        }
    }

    protected void genPlaintext() {
        try {
            logger.debug("genPlaintext");
            int kb = Integer.parseInt(((EditText) getView().findViewById(R.id.plaintext_len_kb)).getText().toString());
            plaintext = StringUtils.repeat('A', kb*1024).getBytes("UTF-8");
            logger.debug("genPlaintext done ({})", plaintext.length);

            dumpLogData(plaintext, "plaintext");
        } catch (Exception e) {
            showExceptionDialog(e);
        }
    }

    protected void encrypt() {
        try {
            logger.debug("encrypt");
            ciphertext= encryptor.encrypt(plaintext);
            logger.debug("encrypt done ({})", ciphertext.length);

            dumpLogData(ciphertext, "ciphertext");
        } catch (Exception e) {
            showExceptionDialog(e);
        }
    }

    protected void decrypt() {
        try {
            logger.debug("decrypt");
            roundtriptext= encryptor.decrypt(ciphertext);
            logger.debug("decrypt done ({})", roundtriptext.length);

            dumpLogData(roundtriptext, "roundtriptext");

            if (!ArrayUtils.isEquals(plaintext, roundtriptext)) {
                throw new RuntimeException("plaintext did not roundtrip");
            }
        } catch (Exception e) {
            showExceptionDialog(e);
        }
    }

    protected void dumpLogData(byte[] data, String filename) throws IOException {
        File file= new File(getActivity().getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS), filename);
        logger.debug("dumping {}", file);
        FileOutputStream stream= new FileOutputStream(file);
        stream.write(data);
        stream.close();
    }

    protected void showExceptionDialog(Exception e) {
        logger.error("{}", e);
        new AlertDialog.Builder(getContext())
                .setTitle(e.getClass().getSimpleName())
                .setMessage(e.getLocalizedMessage())
                .setPositiveButton(android.R.string.ok, null)
                .show();
    }
}
