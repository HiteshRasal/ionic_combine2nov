package com.finoux;


import android.annotation.TargetApi;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Enumeration;

public class PNSignature {
    
    protected static final char SPLIT = '#';
    public static final String KEYPROVIDER = "RSA";
    public static final String KEYALGO = "SHA256withRSA";
    
    /**
     *
     * @param alias
     * @return
     */
    
    @TargetApi(Build.VERSION_CODES.M)
    public String generateKeys(String alias) {
        
        KeyPairGenerator kpg = null;
        SecureRandom random = null;
        ArrayList myKeys = null;
        PublicKey pub = null;
        String publickey_string = null;
        try {
            
            int version = Build.VERSION.SDK_INT;
            
            pub = storeKeysIntoVault(version, kpg, alias, context);
            publickey_string = savePublicKey(pub,true);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return publickey_string;
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
    public PublicKey storeKeysIntoVault(int version, KeyPairGenerator pkpg, String alias, Context context) {
        try {
            PublicKey pub = null;
            PrivateKey priv = null;
            if (version >= 23) {
                pkpg = KeyPairGenerator.getInstance(KEYPROVIDER, "AndroidKeyStore");
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
                
                pkpg = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
                
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
                priv = kp.getPrivate();
                
                return pub;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return null;
    }
    
    
    //---------------------------------------------------------------------------
    
    /**
     *
     * @param alias
     * @return
     */
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
                if(alias_names.equals(alias)){
                    return true;
                }
            }
            
            System.out.println("alias name: " + alias_names);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
    
    //-------------------------------------------------------------------------
    
    /**
     *
     * @param alias
     * @param uniqueKey
     * @return
     */
    public byte[] generateSignature(String alias, String uniqueKey) {
        byte[] signature = null;
        Signature s;
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            
            
            PrivateKey privateKey = (PrivateKey) ks.getKey(alias, null);
            
            s = Signature.getInstance(KEYALGO);
            s.initSign(privateKey);
            s.update(uniqueKey.getBytes("UTF-8"));
            signature = s.sign();
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return signature;
        
    }
    
    
    //-------------------------------------------------------------------------
    
    /**
     *
     * @param alias
     * @return
     */
    public boolean deleteKey(String alias) {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            boolean check=check_alias(alias);
            
            if(check){
                keyStore.deleteEntry(alias);
                return true;
            }
            else{
                Log.d("Alias not valid","");
                
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        return false;
    }
    
    //......................................................................................
    
    /**
     * @param key
     * @return
     */
    public static String savePublicKey(PublicKey key, boolean test) {
        RSAPublicKeySpec spec = null;
        byte[] data = null;
        StringBuilder buf = null;
        try {
            Log.d("Original Pub","="+key);
            KeyFactory kf = KeyFactory.getInstance(KEYPROVIDER);
            spec = kf.getKeySpec(key, RSAPublicKeySpec.class);
            buf = new StringBuilder();
            buf.append(spec.getModulus().toString(16))
            .append("#")
            .append(spec.getPublicExponent().toString(16));
            Log.d("Original Pub","="+key);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return buf.toString();
    }
}
