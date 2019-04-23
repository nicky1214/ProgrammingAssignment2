package com.example.csepa2;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

public class CreateX509 {

    InputStream fis;

    {
        try {
            fis = new FileInputStream("C:\\Users\\User\\Desktop\\PA2\\CA.crt");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    CertificateFactory cf;

    {
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            e.printStackTrace();
        }
    }

    X509Certificate CAcert;

    {
        try {
            CAcert = (X509Certificate)cf.generateCertificate(fis);
        } catch (CertificateException e) {
            e.printStackTrace();
        }
    }

    PublicKey key = CAcert.getPublicKey();

//    CAcert.checkValidity();
//
//    CAcert.verify(key);
//
//





}
