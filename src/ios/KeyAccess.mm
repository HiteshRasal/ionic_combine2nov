/********* KeyAcess.m Cordova Plugin Implementation *******/
#import "KeyAccess.h"
#define SERVICE_NAME @"keyData"

#include <iomanip>
#include "pem.h"
#include "engine.h"
#include <sstream>
#include "bio.h"
#include "rsa.h"

@implementation KeyAccess

#pragma mark- callback methods

- (void)deleteMethod:(CDVInvokedUrlCommand*)command
{
    keychain  =[[Keychain alloc] initWithService:SERVICE_NAME withGroup:nil];
    CDVPluginResult* pluginResult = nil;
     NSString *keyForVal=@"VPKey";
    
    if (keyForVal != nil && [keyForVal length] > 0) {
        
        NSString *msg=[self removeData:keyForVal];
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:msg];
    } else {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR];
    }
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}
#pragma mark - generate private public key
- (void)getPublicKey:(CDVInvokedUrlCommand*)command
{   keychain  =[[Keychain alloc] initWithService:SERVICE_NAME withGroup:nil];
    CDVPluginResult* pluginResult = nil;
    
    NSString *publicKey =[self generateKeysExample];
    NSLog(@"publicKey is %@",publicKey);
    pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:publicKey];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

#pragma mark- signature
- (void)geneSigning:(CDVInvokedUrlCommand*)command
{
    keychain  =[[Keychain alloc] initWithService:SERVICE_NAME withGroup:nil];
    CDVPluginResult* pluginResult = nil;
    NSString* strToenc = [command.arguments objectAtIndex:0];
    NSString *keyForSign=[self fetchData:@"VPKey"];
    
    if ([keyForSign isEqualToString:@"Private key was not generated"]) {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:keyForSign];
    }else{
        NSString *string = [self signHeader:strToenc withPrivateKey:keyForSign];
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:string];
    }
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

#pragma mark - keyChain methods
-(NSString *)storeData:(NSString *)keyForVal data:(NSString *)storeVal{
    NSString *key =keyForVal;
    NSString *errorMsg=@"Failed to Generate Keys";
    NSString *successMsg=@"Successfully store key";
    NSData * value = [storeVal dataUsingEncoding:NSUTF8StringEncoding];
    
    if([keychain insert:key :value])
    {
        return successMsg;
    }
    else{
        return  errorMsg;
    }
}

-(NSString *)fetchData :(NSString *)keyForVal{
    NSString *key= keyForVal;
    NSString *errorMsg=@"Private key was not generated";
    NSData * data =[keychain find:key];
    NSString *fetchString;
    if(data == nil)
    {
        return errorMsg;
    }
    else
    {
        fetchString=[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        return fetchString;
    }
    
}

-(NSString *)removeData :(NSString *)keyForVal{
    NSString *key =keyForVal;
    NSString *success= @"Successfully key deleted";
    NSString *errorMsg= @"Fail to delete key";
    if([keychain remove:key])
    {
        return success;
    }
    else
    {
        return errorMsg;
    }
}

#pragma mark - generate public private key

NSString *letters = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

-(NSString *) randomStringWithLength: (int) len {
    
    NSMutableString *randomString = [NSMutableString stringWithCapacity: len];
    
    for (int i=0; i<len; i++) {
        [randomString appendFormat: @"%C", [letters characterAtIndex: arc4random_uniform([letters length])]];
    }
    
    return randomString;
}

- (NSString *)generateKeysExample
{
    error = [[BDError alloc] init];
    
    
    RSACryptor = [[BDRSACryptor alloc] init];
    
    RSAKeyPair = [RSACryptor generateKeyPairWithKeyIdentifier:@"keyChain.com.da" randomKey:[self randomStringWithLength:16] error:error];
    NSString *publicKey= RSAKeyPair.publicKey;
    NSString *msg=[self storeData:@"VPKey" data:RSAKeyPair.privateKey];
    if ([msg isEqualToString:@"Failed to Generate Keys"]) {
        return msg;
    }else{
        
        return publicKey;
    }
}


- (NSString*) signHeader:(NSString*) pTextString withPrivateKey: (NSString*) pPrivateKey {
    
    int retEr;
    char* text = (char*) [pTextString UTF8String];
    unsigned char *data;
    unsigned int dataLen;
    
    // converting nsstring base64 private key to openssl RSA key
    
    BIO *mem = NULL;
    RSA *rsa_private = NULL;
    char *private_key = (char*)[pPrivateKey UTF8String];
    
    mem = BIO_new_mem_buf(private_key, strlen(private_key));
    if (mem == NULL)
    {
        char buffer[120];
        ERR_error_string(ERR_get_error(), buffer);
        fprintf(stderr, "OpenSSL error: %s", buffer);
        exit(0);
    }
    
    rsa_private = PEM_read_bio_RSAPrivateKey(mem, NULL, NULL, NULL);
    BIO_free (mem);
    if (rsa_private == NULL)
    {
        char buffer[120];
        ERR_error_string(ERR_get_error(), buffer);
        fprintf(stderr, "OpenSSL error: %s", buffer);
        exit(0);
    }
    // end of convertion
    
    data = (unsigned char *) text;
    dataLen = strlen(text);
    
    //// creating signature
    // sha1
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char sign[256];
    unsigned int signLen;
    
    SHA256(data, dataLen, hash);
    
    //  signing
    retEr = RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sign, &signLen, rsa_private);
    
    //  printf("Signature len gth = %d\n", signLen);
    printf("RSA_sign: %s\n", (retEr == 1) ? "RSA_sign success" : "RSA_sign error");
    
    //  convert unsigned char -> std:string
    std::stringstream buffer;
    for (int i = 0; i < 128; i++)
    {
        buffer << std::hex << std::setfill('0');
        buffer << std::setw(2)  << static_cast<unsigned>(sign[i]);
    }
    std::string signature = buffer.str();
    
    //  convert std:string -> nsstring
    NSString *signedMessage = [NSString stringWithCString:signature.c_str() encoding:[NSString defaultCStringEncoding]];
    
    RSA_free(rsa_private);
    
    return signedMessage;
}

@end
