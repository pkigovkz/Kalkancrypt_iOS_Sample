//
//  ViewController.m
//  XmlTest
//
//  Created by aslan on 12/29/15.
//  Copyright © 2015 knca. All rights reserved.
//
//  Modified on 11/2020.
#import "ViewController.h"

const xmlChar* NS_XMLDSIG = BAD_CAST "http://www.w3.org/2000/09/xmldsig#";
const xmlChar* C14N_OMIT_COMMENTS = BAD_CAST "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const xmlChar* C14N_WITH_COMMENTS = BAD_CAST "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
const xmlChar* ALG_GOST34310 = BAD_CAST "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311";
const xmlChar* ALG_TRANSFORM = BAD_CAST "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const xmlChar* ALG_GOST34311 = BAD_CAST "http://www.w3.org/2001/04/xmldsig-more#gost34311";
const xmlChar* ALG_RSA256 = BAD_CAST "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const xmlChar* ALG_SHA256 = BAD_CAST "http://www.w3.org/2001/04/xmlenc#sha256";
const xmlChar* ALG_RSA = BAD_CAST "http://www.w3.org/2001/04/xmldsig-more#rsa-sha1";
const xmlChar* ALG_SHA1 = BAD_CAST "http://www.w3.org/2001/04/xmldsig-more#sha1";

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UITextView *txtSignedXml;

@end

@implementation ViewController
- (IBAction)signXml:(id)sender {
    
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *basePath = ([paths count] > 0) ? [paths objectAtIndex:0] : nil;
    
//    NSString *pkcs12_path = [[NSBundle bundleForClass:[self class]] pathForResource:@"RSA256_bba3ff3629edcbc6b187a69d850dfeefeed64621" ofType:@"p12"];
    NSString *pkcs12_path = [[NSBundle bundleForClass:[self class]] pathForResource:@"GOSTKNCA_4f05e9ce6cab58539f494d95d9dea89c7132d64f" ofType:@"p12"];
//    NSString *pkcs12_path = [[NSBundle bundleForClass:[self class]] pathForResource:@"GOSTKZ_e56fe5a0899f787815adaf5d256da7a0a70c2c13" ofType:@"p12"];
    
    NSData *xmlData = [NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"test" ofType:@"xml"]];
    if(!xmlData) {
        NSLog(@"Xml was not loaded");
    }
    unsigned char *cXml = (unsigned char*)malloc(xmlData.length);
    [xmlData getBytes:cXml length:xmlData.length];
    cXml[xmlData.length] = 0x0;
    NSLog(@"original xml = %s", cXml);
    
    
    xmlDocPtr doc = NULL;
    xmlNodePtr root = NULL, signEl = NULL, sInfoEl = NULL, canMethEl = NULL, signMethEl = NULL, refEl = NULL, transEl = NULL, tranEl = NULL, tran2El = NULL, digMethEl = NULL, digValEl = NULL, sigValEl = NULL, kInfoEl = NULL, x509DataEl = NULL, x509CertEl = NULL;
    
    FILE *fp;
    PKCS12 *p12;
    EVP_PKEY *pkey;
    X509 *cert;
    int err;
    
    STACK_OF(X509) *ca = NULL;
    NSLog(@"PKCS#12: %@", pkcs12_path);
    if([[NSFileManager defaultManager] fileExistsAtPath:pkcs12_path]) {
        NSLog(@"ok, pfile exists!");
    } else {
        NSLog(@"error, pfile does not exists!");
    }
    
    fp = fopen([pkcs12_path UTF8String], "rb");
    p12 = d2i_PKCS12_fp(fp, NULL);
    fclose (fp);
    if (!p12) {
        fprintf(stderr, "Error reading PKCS#12 file\n");
        ERR_print_errors_fp(stderr);
    }
    
    if (!PKCS12_parse(p12, "123456", &pkey, &cert, &ca)) { //Error at parsing or password error
        fprintf(stderr, "Error parsing PKCS#12 file\n");
        ERR_print_errors_fp(stderr);
    }
    
    int len;
    unsigned char *buf;
    unsigned char *pem;
    buf = NULL;
    len = i2d_X509(cert, &buf);
    pem = base64encode(buf, len);
//    NSLog(@"pem = %s\n\n", pem);
    
    PKCS12_free(p12);
    
    doc = xmlParseDoc(cXml);
    xmlChar* c14nXML = NULL;
    xmlC14NDocDumpMemory(doc, NULL, 0, NULL, 0, &c14nXML);
    int c14nXMLLen = strlen((char*)c14nXML);
    printf(c14nXML);
    
    EVP_MD_CTX *mdCtx;
    EVP_MD *md;
    xmlChar *xmlHashAlg = ALG_GOST34311;
    xmlChar *xmlSignAlg = ALG_GOST34310;
    
    int algnid = OBJ_obj2nid(cert->cert_info->signature->algorithm);
    if(algnid == NID_id_GostOld34311_95_with_GostOld34310_2004 || algnid == NID_id_Gost34311_95_with_Gost34310_2004) {
        md = EVP_get_digestbynid(NID_id_Gost34311_95);
        xmlHashAlg = ALG_GOST34311;
        xmlSignAlg = ALG_GOST34310;
    } else if(algnid == NID_sha256WithRSAEncryption) {
        md = EVP_sha256();
        xmlHashAlg = ALG_SHA256;
        xmlSignAlg = ALG_RSA256;
    } else if(algnid == NID_sha1WithRSAEncryption) {
        md = EVP_sha1();
        xmlHashAlg = ALG_SHA1;
        xmlSignAlg = ALG_RSA;
    }
    unsigned char *cHash = (unsigned char*)malloc(EVP_MD_size(md));
    unsigned int cHashLen;
    mdCtx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdCtx, md, NULL);
    EVP_DigestUpdate(mdCtx, c14nXML, c14nXMLLen);
    EVP_DigestFinal_ex(mdCtx, cHash, &cHashLen);
    EVP_MD_CTX_cleanup(mdCtx);

    char *base64Digest = base64encode(cHash, cHashLen);
    NSLog(@"Encoded hash: %s", base64Digest);
    
    xmlXPathContextPtr xpathCtx;
    xmlXPathObjectPtr xpathObj;
    xmlNodeSetPtr sInfoNS;
    
    // создаем Signature и заполняем
    root = xmlDocGetRootElement(doc);
    signEl = xmlNewNode(NULL, BAD_CAST "ds:Signature");
    xmlNsPtr signNS = xmlNewNs(signEl, NS_XMLDSIG, BAD_CAST "ds");
    xmlAddChild(root, signEl);
    sInfoEl = xmlNewChild(signEl, signNS, BAD_CAST "SignedInfo", NULL);
    canMethEl = xmlNewChild(sInfoEl, signNS, BAD_CAST "CanonicalizationMethod", NULL);
    xmlNewProp(canMethEl, BAD_CAST "Algorithm", C14N_OMIT_COMMENTS);
    signMethEl = xmlNewChild(sInfoEl, signNS, BAD_CAST "SignatureMethod", NULL);
    xmlNewProp(signMethEl, BAD_CAST "Algorithm", xmlSignAlg);
    refEl = xmlNewChild(sInfoEl, signNS, BAD_CAST "Reference", NULL);
    xmlNewProp(refEl, BAD_CAST "URI", NULL);
    transEl = xmlNewChild(refEl, signNS, BAD_CAST "Transforms", NULL);
    tranEl = xmlNewChild(transEl, signNS, BAD_CAST "Transform", NULL);
    xmlNewProp(tranEl, BAD_CAST "Algorithm", ALG_TRANSFORM);
    tran2El = xmlNewChild(transEl, signNS, BAD_CAST "Transform", NULL);
    xmlNewProp(tran2El, BAD_CAST "Algorithm", C14N_WITH_COMMENTS);
    digMethEl = xmlNewChild(refEl, signNS, BAD_CAST "DigestMethod", NULL);
    xmlNewProp(digMethEl, BAD_CAST "Algorithm", xmlHashAlg);
    digValEl = xmlNewChild(refEl, signNS, BAD_CAST "DigestValue", BAD_CAST base64Digest);
    
    xpathCtx = xmlXPathNewContext(doc);
    xmlXPathRegisterNs(xpathCtx, BAD_CAST "ds", NS_XMLDSIG);
    xpathObj = xmlXPathEvalExpression(BAD_CAST "(//. | //@* | //namespace::*)[ancestor-or-self::ds:SignedInfo]", xpathCtx);
    sInfoNS = xpathObj->nodesetval;
    
    xmlChar *c14nSInfo = NULL;
    xmlC14NDocDumpMemory(doc, sInfoNS, 0, NULL, 1, &c14nSInfo);
    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx);
    
    int c14nSInfoLen = strlen((char*)c14nSInfo);
    NSLog(@"Canonicalized SignedInfo = %s", c14nSInfo);
    NSLog(@"key size = %d", EVP_PKEY_size(pkey));
    
    // подписываем
    unsigned char *cSignature = (unsigned char*)malloc(EVP_PKEY_size(pkey));
    unsigned int sigLen;
    EVP_SignInit_ex(mdCtx, md, NULL);
    EVP_SignUpdate (mdCtx, c14nSInfo, c14nSInfoLen);
    EVP_SignFinal (mdCtx, cSignature, &sigLen, pkey);
    
    // вообще, так надо проверять каждую функцию библиотеки провайдера
    // и что-то предпринимать
    if (err != 1) {
        ERR_print_errors_fp(stderr);
    }

    char *base64Signature = base64encode(cSignature, sigLen);
    NSLog(@"Encoded signature: %s", base64Signature);
    
    // дописываем xml
    sigValEl = xmlNewChild(signEl, signNS, BAD_CAST "SignatureValue", BAD_CAST base64Signature);
    kInfoEl = xmlNewChild(signEl, signNS, BAD_CAST "KeyInfo", NULL);
    x509DataEl = xmlNewChild(kInfoEl, signNS, BAD_CAST "X509Data", NULL);
    x509CertEl = xmlNewChild(x509DataEl, signNS, BAD_CAST "X509Certificate", BAD_CAST pem);

    // выдаем подписанный xml
    xmlChar *outXML;
    int outXMLSize;
    xmlDocDumpMemoryEnc(doc, &outXML, &outXMLSize, "UTF-8");
    NSLog(@"signed xml = %s", outXML);
    [self.txtSignedXml setText:[NSString stringWithUTF8String:outXML]];
    
    // сохраняем в файл
    NSData *signedXML = [NSData dataWithBytes:outXML length:outXMLSize];
    NSString *signedXMLPath = [basePath stringByAppendingString:@"/signedXML.xml"];
    NSLog(signedXMLPath);
    [signedXML writeToFile:signedXMLPath atomically:NO];

    xmlFreeDoc(doc);
    xmlCleanupParser();
    xmlMemoryDump();
    EVP_PKEY_free(pkey);
    X509_free(cert);
    EVP_MD_CTX_destroy(mdCtx);
}

- (void)viewDidLoad {
    [super viewDidLoad];
    
    // надо инициализировать при запуске приложения
    OpenSSL_add_all_algorithms();
    ENGINE_load_gost();
    ERR_load_crypto_strings();
    
    // а таким образом очищаем всё вышеуказанное
    //EVP_cleanup();
    //ERR_free_strings();
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
}

- (IBAction)genereateGostKeyPair:(id)sender {
    
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx;
    int returnCode;
    int nid = OBJ_txt2nid("gost2004");
    int param_nid = OBJ_txt2nid("id-Gost34310-2004-PKIGOVKZ-A-ParamSet");
    
    ctx = EVP_PKEY_CTX_new_id(nid, NULL);
    if (!ctx) {
        NSLog(@"Could not load context");
        return;
    }
    
    returnCode = EVP_PKEY_paramgen_init(ctx);
    if (returnCode != 1) {
        NSLog(@"Could not initialize parameter generation. Code: %d", returnCode);
        return;
    }
    returnCode = EVP_PKEY_CTX_ctrl(ctx, nid, EVP_PKEY_OP_PARAMGEN, EVP_PKEY_CTRL_RSA_PADDING, param_nid, NULL);
    if (returnCode != 1) {
        NSLog(@"Could not send control operation. Code: %d", returnCode);
        return;
    }
    returnCode = EVP_PKEY_keygen_init(ctx);
    if (returnCode != 1) {
        NSLog(@"Could not initialize key pair generation. Code: %d", returnCode);
        return;
    }
    returnCode = EVP_PKEY_keygen(ctx, &key);
    if (returnCode != 1) {
        NSLog(@"Could not generate key pair. Code: %d", returnCode);
        return;
    }
    EVP_PKEY_CTX_free(ctx);
    
    NSString *privatePart = @"privateGost.pem";
    NSString *publicPart = @"publicGost.pem";
    if ([self saveGostToPath:key
                 privatePart:privatePart publicPart:publicPart
                    withPass:@"newpass"]) {
        NSLog(@"Gost key pair has been generated. Pems: %@, %@", privatePart, publicPart);
    }
    EVP_PKEY_free(key);
    
}

- (IBAction)genereateRSAKeyPair:(id)sender {
    
    int bits = 2048;
    BIGNUM *bigNumber = NULL;
    RSA *rsa = NULL;
    
    @try {
        
        int returnCode;
        
        bigNumber = BN_new();
        if (!bigNumber) {
            NSLog(@"Failed to allocate memory for variable: bigNumber");
            return;
            
        }
        
        rsa = RSA_new();
        if (!rsa) {
            NSLog(@"Failed to allocate memory for variable: rsa");
            return;
        }
        
        returnCode = BN_set_word(bigNumber, RSA_F4);
        if (returnCode != 1) {
            NSLog(@"Failed to generate key, function BN_set_word returned with %d", returnCode);
            return;
        }
        
        returnCode = RSA_generate_key_ex(rsa, bits, bigNumber, NULL);
        if (returnCode != 1) {
            NSLog(@"Failed to generate RSA key, function RSA_generate_key_ex returned with %d", returnCode);
            return;
        }
       
        if (rsa != nil){
            NSString *pem = @"rsa.pem";
            [self saveRsaToPath:rsa name:pem withPass:@"newpass"];
            NSLog(@"RSA key pair has been generated. Pem: %@", pem);
        } else {
            return;
        }
    }
    @catch (NSException *exc) {
        
        if (exc != nil) {
            NSLog(@"Exception in create rsa %@", [exc description]);
        }
        RSA_free(rsa);
        return;
    }
    @finally {
        
        BN_free(bigNumber);
        
    }
}

-(BOOL)saveRsaToPath:(RSA*)rsa name:(NSString*) fileName withPass:(NSString*)password {
    
    NSArray* paths = [[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask];
    NSString* docPath = [[paths objectAtIndex:0] path];
    NSString* keyPath = [NSString stringWithFormat:@"%@/%@", docPath, fileName];
    
    BOOL isExist = [[NSFileManager defaultManager] fileExistsAtPath:keyPath];
    if (isExist){
        [[NSFileManager defaultManager] removeItemAtPath:keyPath error:nil];
    }
    
    FILE* file = NULL;
    
    @try {
        
        int returnCode;
        
        file = fopen([keyPath fileSystemRepresentation], "w");
        if (!file) {
            NSLog(@"Failed to open file for write: %@", keyPath);
            return false;
        }
     
        returnCode = PEM_write_RSAPrivateKey(file, rsa, EVP_aes_128_cbc(), NULL, 0, NULL, [password UTF8String]);
        
        if (returnCode != 1) {
            NSLog(@"Failed to write key file, function PEM_write_RSAPrivateKey returned with %d", returnCode);
            return false;
        }
        fclose(file);
        return true;
    }
    @catch (NSException *exp) {
        
        if (exp != nil) {
             NSLog(@"Saving RSA failure %@", [exp description]);
        }
        return false;
    }
    @finally {
        fclose(file);
    }
}

-(BOOL)saveGostToPath:(EVP_PKEY*)key privatePart:(NSString*) privatePart publicPart:(NSString*) publicPart withPass:(NSString*)password {
    
    NSArray* paths = [[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask];
    NSString* docPath = [[paths objectAtIndex:0] path];
    NSString* privatePath = [NSString stringWithFormat:@"%@/%@", docPath, privatePart];
    NSString* publicPath = [NSString stringWithFormat:@"%@/%@", docPath, publicPart];
    
    BOOL isExist = [[NSFileManager defaultManager] fileExistsAtPath:privatePath];
    if (isExist){
        [[NSFileManager defaultManager] removeItemAtPath:privatePath error:nil];
    }
    isExist = [[NSFileManager defaultManager] fileExistsAtPath:publicPath];
    if (isExist){
        [[NSFileManager defaultManager] removeItemAtPath:publicPath error:nil];
    }
    
    FILE *private = NULL, *public = NULL;
    
    @try {
        
        int returnCode;
        
        private = fopen([privatePath fileSystemRepresentation], "w");
        if (!private) {
            NSLog(@"Failed to open file for write: %@", privatePath);
            return false;
        }
        public = fopen([publicPath fileSystemRepresentation], "w");
        if (!public) {
            NSLog(@"Failed to open file for write: %@", publicPath);
            return false;
        }
     
        returnCode = PEM_write_PrivateKey(private,key, EVP_aes_128_cbc(), NULL, 0, NULL, [password UTF8String]);
        // без шифрования закрытого ключа
        //returnCode = PEM_write_PrivateKey(private,key, NULL, NULL, 0, NULL, NULL);
        if (returnCode != 1) {
            NSLog(@"Failed to write private part, function PEM_write_PrivateKey returned with %d", returnCode);
            return false;
        }
        returnCode = PEM_write_PUBKEY(public, key);
        if (returnCode != 1) {
            NSLog(@"Failed to write public part, function PEM_write_PUBKEY returned with %d", returnCode);
            return false;
        }
        return true;
    }
    @catch (NSException *exp) {
        
        if (exp != nil) {
             NSLog(@"Saving gost failure %@", [exp description]);
        }
        return false;
    }
    @finally {
        fclose(private);
        fclose(public);
    }
}

@end
