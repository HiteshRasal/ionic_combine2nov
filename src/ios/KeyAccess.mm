/********* KeyAcess.m Cordova Plugin Implementation *******/
#import "KeyAccess.h"
#define SERVICE_NAME @"keyData"
#define GROUP_NAME @"com.finoux.KeyAcess.com.apps.shared"

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
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:keyForVal];
        [self removeData:keyForVal];
    } else {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR];
    }
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}
#pragma mark - generate private public key
- (void)getPublicKey:(CDVInvokedUrlCommand*)command
{   keychain  =[[Keychain alloc] initWithService:SERVICE_NAME withGroup:nil];
    CDVPluginResult* pluginResult = nil;
    
    NSMutableArray *value=[self generateKeysExample];
    NSMutableDictionary *keyPair=[[NSMutableDictionary alloc]init];
    [keyPair setValue:[value objectAtIndex:0] forKey:@"PublicKey"];
    [keyPair setValue:[value objectAtIndex:1] forKey:@"PrivateKey"];
    NSLog(@"dictionary is %@",keyPair);
    pluginResult=[CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:keyPair];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

#pragma mark- signature
- (void)geneSigning:(CDVInvokedUrlCommand*)command
{
    keychain  =[[Keychain alloc] initWithService:SERVICE_NAME withGroup:nil];
    CDVPluginResult* pluginResult = nil;
    NSString* strToenc = [command.arguments objectAtIndex:0];
    NSString *keyForSign=[self fetchData:@"VPKey"];
    NSString *string = [self signHeader:strToenc withPrivateKey:keyForSign];
    pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:string];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

#pragma mark - keyChain methods
-(void)storeData:(NSString *)keyForVal data:(NSString *)storeVal{
    NSString *key =keyForVal;
    NSData * value = [storeVal dataUsingEncoding:NSUTF8StringEncoding];
    
    if([keychain insert:key :value])
    {
        NSLog(@"Successfully added data");
    }
    else
        NSLog(@"Failed to  add data");
}

-(NSString *)fetchData :(NSString *)keyForVal{
    NSString *key= keyForVal;
    NSData * data =[keychain find:key];
    NSString *fetchString;
    if(data == nil)
    {
        NSLog(@"Keychain data not found");
    }
    else
    {
        fetchString=[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
    return fetchString;
}

-(void)removeData :(NSString *)keyForVal{
    NSString *key =keyForVal;
    if([keychain remove:key])
    {
        NSLog(@"Successfully removed data");
    }
    else
    {
        NSLog(@"Unable to remove data");
    }
}

#pragma mark - generate public private key
- (NSMutableArray *)generateKeysExample
{
    error = [[BDError alloc] init];
    
    NSMutableArray *keyArray=[NSMutableArray array];
    
    RSACryptor = [[BDRSACryptor alloc] init];
    
    RSAKeyPair = [RSACryptor generateKeyPairWithKeyIdentifier:@"keyChain.com.da" randomKey:@"abcdefghijklmnopqrstuvwxyz123456789" error:error];
    [keyArray addObject:RSAKeyPair.publicKey];
    NSLog(@"publicKey here11 %@",RSAKeyPair.publicKey);
    [keyArray addObject:RSAKeyPair.privateKey];
    NSLog(@"RSAKeyPair.privateKey here11 %@",RSAKeyPair.privateKey);
    [self storeData:@"VPKey" data:RSAKeyPair.privateKey];
    NSLog(@"keyArray %@",keyArray);
    
    return keyArray;
}
-(NSString *)signing :(NSString *)strTosign publicKey:(NSString *)publicKey{
    
    
    NSString *signature=[RSACryptor encrypt:strTosign key:publicKey error:error];
    NSString *recoveredText =[RSACryptor decrypt:signature key:RSAKeyPair.privateKey error:error];
    
    BDDebugLog(@"Recovered Text:\n%@", recoveredText);
    return  signature;
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
