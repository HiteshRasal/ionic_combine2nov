package com.finoux;


import android.annotation.TargetApi;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.KeyChain;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Enumeration;

import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import java.io.StringWriter;
import java.io.IOException;

public class PNSignature {
    /** Our split character. */
    protected static final char SPLIT = '#';
    public static final String KEYPROVIDER = "RSA";
    public static final String KEYALGO = "SHA256withRSA";
    public static final String SHARED_PREF = "pref";
    
    
    @TargetApi(Build.VERSION_CODES.M)
    public String generateKeys(String alias, Context context) {
        try {    
            PublicKey pub = storeKeysIntoVault(alias, context);
            return toPEMString(pub);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }
    
    /**
     *
     * @param version
     * @param pkpg
     * @param alias
     * @param context
     * @return
     */
    @TargetApi(Build.VERSION_CODES.M)
    public PublicKey storeKeysIntoVault(String alias, Context context) {
        int version = Build.VERSION.SDK_INT;

        try {
            PublicKey pub = null;
            PrivateKey priv = null;
            if (version >= 23) {
                KeyPairGenerator pkpg = KeyPairGenerator.getInstance(KEYPROVIDER, "AndroidKeyStore");
                pkpg.initialize(new KeyGenParameterSpec.Builder(
                                                                alias,
                                                                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                                .setDigests(KeyProperties.DIGEST_SHA256,
                                            KeyProperties.DIGEST_SHA512)
                                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                                .build());
                KeyPair kp = pkpg.generateKeyPair();
                pub = kp.getPublic();
                priv = kp.getPrivate();
                return pub;
            } else {
                Calendar start = Calendar.getInstance();
                Calendar end = Calendar.getInstance();
                end.add(Calendar.YEAR, 1);
                
                KeyPairGenerator pkpg = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
                
                KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                .setAlias(alias)
                .setSubject(new X500Principal("CN=Sample Name, O=Android Authority"))
                .setSerialNumber(BigInteger.ONE)
                .setStartDate(start.getTime())
                .setEndDate(end.getTime())
                .build();
                
                pkpg.initialize(spec);
                KeyPair kp = pkpg.generateKeyPair();
                pub = kp.getPublic();
                return pub;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return null;
    }
    //-------------------------------------------------------------------------
    
    
    public boolean check_alias(String alias) {
        Enumeration<String> aliases;
        KeyStore ks = null;
        String alias_names = null;
        try {
            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            Enumeration enumeration = ks.aliases();
            while (enumeration.hasMoreElements()) {
                alias_names = (String) enumeration.nextElement();
                if (alias_names.equals(alias)) {
                    return true;
                }
            }
            
            System.out.println("alias name: " + alias_names);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
    //......................................................................................
    
    public byte[] generateSignature(String alias, String uniqueKey, Context context) {
        byte[] signature = null;
        Signature s = null;
        KeyStore ks = null;
        PrivateKey privateKey = null;
        
        try {
            
            int version = Build.VERSION.SDK_INT;
            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            
            privateKey = (PrivateKey) ks.getKey(alias, null);
            s = Signature.getInstance(KEYALGO);
            s.initSign(privateKey);
            s.update(uniqueKey.getBytes("UTF-8"));
            signature = s.sign();
            return signature;
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return null;
        
    }
    //......................................................................................
    
    
    public boolean deleteKey(String alias, Context context) {
        int version = Build.VERSION.SDK_INT;
        
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            boolean check = check_alias(alias);
            
            if (check) {
                keyStore.deleteEntry(alias);
                return true;
            } else {
                Log.d("Alias not valid", "");
                
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return false;
    }
    //......................................................................................
    
    /**
     * @param key
     * @return
     */
    public static String toPEMString(PublicKey publicKey) throws IOException {
        StringWriter sw = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(sw);
        pemWriter.writeObject(publicKey);
        pemWriter.close();
        return sw.toString();
    }
    
    
}