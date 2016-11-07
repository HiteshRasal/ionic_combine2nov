package com.finoux;

import android.util.Base64;
import android.util.Log;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;
import org.json.JSONArray;
import org.json.JSONException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import android.content.Context;

/**
 * This class echoes a string called from JavaScript.
 */
public class KeyAccess extends CordovaPlugin {
    String message;
    
    @Override
    public boolean execute(String action, JSONArray args,CallbackContext callbackContext) throws JSONException {
        if (action.equals("getPublicKey")) {
            message ="VPKey";
            this.getPublicKey(message, callbackContext);
            return true;
        }
        
        else if (action.equals("geneSigning")) {
            String value = args.getString(0);
            try {
                this.geneSigning(message,value, callbackContext);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return true;
        } else if (action.equals("deleteMethod")) {
            String delete_key = args.getString(0);
            try {
                this.deleteMethod(message, callbackContext);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return true;
        }
        return false;
    }
    
    //Generate PublicKey Method
    
    private void getPublicKey(String alias, final CallbackContext callbackContext){
        
        try {
            Context context=this.cordova.getActivity().getApplicationContext();
            PNSignature pnsig = new PNSignature();
            
            String pub = pnsig.generateKeys(alias,context);
            
            boolean test=pnsig.check_alias(alias);
            
            if(test){
                Log.d("Test","= "+test);
            }else{
                Log.d("failed","");
            }
            callbackContext.success(pub);
            
        }catch (Exception e){
            e.printStackTrace();
        }
        
    }
    // Generate Signature Method
    
    private void geneSigning(
                             String alias
                             , String uiactualData
                             , CallbackContext callbackContext
                             ) {
        Context context=this.cordova.getActivity().getApplicationContext();
        PNSignature pnsig = new PNSignature();
        
        byte[] realSig = pnsig.generateSignature(alias, uiactualData,context);
        
        String newToken = Base64.encodeToString(realSig, Base64.DEFAULT);
        
        
        callbackContext.success(newToken);
        
    }
    
    //Delete Method
    
    private void deleteMethod(String delete_key, CallbackContext callbackContext) {
        Context context=this.cordova.getActivity().getApplicationContext();
        PNSignature pnsig = new PNSignature();
        boolean confirm_delete=pnsig.deleteKey(delete_key,context);
        
        if(confirm_delete){
            callbackContext.success("delete success");
        }else{
            callbackContext.success("delete fail");
        }
        
    }
    
    
}
