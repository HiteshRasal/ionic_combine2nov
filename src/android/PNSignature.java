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

	public static final String KEYPROVIDER 						= 	"RSA";
	public static final String KEYALGO 							= 	"SHA256withRSA";

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
            kpg = KeyPairGenerator.getInstance(KEYPROVIDER, "AndroidKeyStore");
            random = new SecureRandom();
            kpg.initialize(new KeyGenParameterSpec.Builder(
                                                           alias,
                                                           KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                           .setDigests(KeyProperties.DIGEST_SHA256,
                                       KeyProperties.DIGEST_SHA512)
                           .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                           .build());
            
            KeyPair kp = kpg.generateKeyPair();
            pub = kp.getPublic();
            publickey_string=savePublicKey(pub);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return publickey_string;
    }
    
    
    //-------------------------------------------------------------------------
    
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
     * @param stored
     * @return
     * @throws GeneralSecurityException
     */
    public static PublicKey loadPublicKey(String stored) throws GeneralSecurityException {
        byte[] data = Base64.decode(stored, Base64.DEFAULT);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
        KeyFactory fact = KeyFactory.getInstance(KEYPROVIDER);
        return fact.generatePublic(spec);
    }
    
    
    /**
     * @param publ
     * @return
     */
    public static String savePublicKey(PublicKey publ) {
        X509EncodedKeySpec spec = null;
        try {
            KeyFactory fact = KeyFactory.getInstance(KEYPROVIDER);
            spec = fact.getKeySpec(publ,
                                   X509EncodedKeySpec.class);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        return Base64.encodeToString(spec.getEncoded(), Base64.DEFAULT);
    }

}
