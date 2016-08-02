package com.paleozogt.androidencryptiondemo;

import android.support.v4.app.Fragment;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MainActivityFragment extends Fragment {
    Logger logger= LoggerFactory.getLogger(getClass());

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

        return view;
    }

    protected void genKey() {
        logger.debug("genKey");
    }

    protected void genPlaintext() {
        logger.debug("genPlaintext");
    }

    protected void encrypt() {
        logger.debug("encrypt");
    }

    protected void decrypt() {
        logger.debug("decrypt");
    }
}
