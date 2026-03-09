#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonCrypto.h>
#import <Security/Security.h>
#import <sqlite3.h>

// VULNERABILITY TEST FILE - Contains intentional security issues for scanner testing

#define API_KEY @"sk-abcdefghijklmnopqrstuvwxyz123456"
#define SECRET_PASSWORD @"MyHardcodedPassword2026!"
#define AWS_KEY @"AKIAIOSFODNN7EXAMPLE"

@interface DatabaseManager : NSObject
@property (nonatomic, assign) sqlite3 *database;
@end

@implementation DatabaseManager

// SQL Injection - sqlite3_exec with format string
- (void)getUser:(NSString *)username {
    NSString *query = [NSString stringWithFormat:@"SELECT * FROM users WHERE name = '%@'", username];
    sqlite3_exec(self.database, [query UTF8String], NULL, NULL, NULL);
}

// SQL Injection - FMDB with format string
- (void)searchUsers:(NSString *)term {
    NSString *sql = [NSString stringWithFormat:@"SELECT * FROM users WHERE name LIKE '%%%@%%'", term];
    [self.db executeQuery:[NSString stringWithFormat:@"SELECT * FROM t WHERE id = '%@'", term]];
}

// SQL Injection - DELETE with format specifier
- (void)deleteUser:(NSString *)userId {
    NSString *sql = [NSString stringWithFormat:@"DELETE FROM users WHERE id = %@", userId];
    sqlite3_exec(self.database, [sql UTF8String], NULL, NULL, NULL);
}

@end

@interface CommandExecutor : NSObject
@end

@implementation CommandExecutor

// Command Injection - NSTask
- (void)runCommand:(NSString *)input {
    NSTask *task = [[NSTask alloc] init];
    [task setLaunchPath:@"/bin/sh"];
    [task setArguments:@[@"-c", [NSString stringWithFormat:@"echo %@", input]]];
    [task launch];
}

// Command Injection - system()
- (void)executeShell:(NSString *)command {
    system([command UTF8String]);
}

// Command Injection - popen()
- (NSString *)readOutput:(NSString *)cmd {
    FILE *fp = popen([cmd UTF8String], "r");
    return @"";
}

@end

@interface WebViewManager : UIViewController
@property (nonatomic, strong) UIWebView *oldWebView;
@property (nonatomic, strong) WKWebView *webView;
@end

@implementation WebViewManager

// XSS - UIWebView (deprecated)
- (void)setupOldWebView {
    self.oldWebView = [[UIWebView alloc] init];
    [self.oldWebView stringByEvaluatingJavaScriptFromString:[NSString stringWithFormat:@"alert('%@')", self.userInput]];
}

// XSS - loadHTMLString with format string
- (void)loadContent:(NSString *)htmlContent {
    [self.webView loadHTMLString:[NSString stringWithFormat:@"<html>%@</html>", htmlContent] baseURL:nil];
}

// XSS - evaluateJavaScript with format string
- (void)executeJS:(NSString *)code {
    [self.webView evaluateJavaScript:[NSString stringWithFormat:@"doSomething('%@')", code] completionHandler:nil];
}

@end

@interface FormatStringBugs : NSObject
@end

@implementation FormatStringBugs

// Format String - NSLog with variable format
- (void)logMessage:(NSString *)userMessage {
    NSLog(userMessage);
}

// Format String - stringWithFormat with variable
- (NSString *)formatData:(NSString *)formatStr {
    return [NSString stringWithFormat:formatStr];
}

// Format String - printf
- (void)printData:(const char *)input {
    printf(input);
}

@end

@interface FileOperations : NSObject
@end

@implementation FileOperations

// Path Traversal - file access with format string
- (NSData *)readFile:(NSString *)filename {
    NSString *path = [NSString stringWithFormat:@"/data/%@", filename];
    return [NSData dataWithContentsOfFile:[NSString stringWithFormat:@"/tmp/%@", filename]];
}

// Path Traversal - path component from user input
- (NSString *)getDocument:(NSString *)userPath {
    return [@"/documents" stringByAppendingPathComponent:userPath];
}

@end

@interface DeserializationBugs : NSObject <NSCoding>
@end

@implementation DeserializationBugs

// Deserialization - insecure NSKeyedUnarchiver
- (id)loadFromData:(NSData *)data {
    return [NSKeyedUnarchiver unarchiveObjectWithData:data];
}

// Deserialization - NSUnarchiver (deprecated)
- (id)loadLegacy:(NSData *)data {
    NSUnarchiver *unarchiver = [[NSUnarchiver alloc] initForReadingWithData:data];
    return [unarchiver decodeObject];
}

// NSCoding protocol conformance
- (void)encodeWithCoder:(NSCoder *)coder {}
- (instancetype)initWithCoder:(NSCoder *)coder { return [super init]; }

@end

@interface CryptoManager : NSObject
@end

@implementation CryptoManager

// Weak Crypto - CC_MD5
- (NSData *)hashMD5:(NSData *)data {
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5(data.bytes, (CC_LONG)data.length, digest);
    return [NSData dataWithBytes:digest length:CC_MD5_DIGEST_LENGTH];
}

// Weak Crypto - CC_SHA1
- (NSData *)hashSHA1:(NSData *)data {
    unsigned char digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(data.bytes, (CC_LONG)data.length, digest);
    return [NSData dataWithBytes:digest length:CC_SHA1_DIGEST_LENGTH];
}

// Weak Crypto - DES
- (NSData *)encryptDES:(NSData *)data {
    CCAlgorithm algorithm = kCCAlgorithmDES;
    return nil;
}

// Weak Crypto - ECB mode
- (NSData *)encryptECB:(NSData *)data {
    CCOptions options = kCCOptionECBMode;
    return nil;
}

@end

@interface RandomBugs : NSObject
@end

@implementation RandomBugs

// Insecure Random - rand()
- (int)generateToken {
    srand((unsigned)time(NULL));
    return rand();
}

// Insecure Random - random()
- (long)getRandomValue {
    srandom((unsigned)time(NULL));
    return random();
}

// Insecure Random - arc4random without uniform
- (uint32_t)getRandomInt {
    return arc4random();
}

@end

@interface NetworkConfig : NSObject <NSURLSessionDelegate>
@end

@implementation NetworkConfig

// Insecure TLS - ATS disabled
// Info.plist: NSAllowsArbitraryLoads = YES

// Insecure TLS - certificate bypass
- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge {
    // setAllowsAnyHTTPSCertificate: YES
    [challenge.sender continueWithoutCredentialForAuthenticationChallenge:challenge];
}

// Insecure TLS - allow invalid certs
- (void)setupNetwork {
    self.allowInvalidCertificates = YES;
    self.validatesDomainName = NO;
}

@end

@interface MemoryBugs : NSObject
@property (nonatomic, strong) NSString *data;
@end

@implementation MemoryBugs

// Memory Management - manual retain/release in ARC
- (void)manualMemory {
    NSObject *obj = [[NSObject alloc] init];
    [obj retain];
    [obj release];
    [obj autorelease];
}

// Memory Management - retainCount
- (void)checkRetain:(NSObject *)obj {
    NSUInteger count = [obj retainCount];
}

// Buffer Overflow - strcpy
- (void)unsafeCopy:(const char *)input {
    char buffer[64];
    strcpy(buffer, input);
    strcat(buffer, "suffix");
}

// Buffer Overflow - sprintf
- (void)unsafeFormat:(const char *)input {
    char buffer[128];
    sprintf(buffer, "data: %s", input);
}

// Buffer Overflow - gets
- (void)unsafeRead {
    char buffer[256];
    gets(buffer);
}

@end

@interface KeychainMisuse : NSObject
@end

@implementation KeychainMisuse

// NSUserDefaults for secrets
- (void)saveCredentials:(NSString *)password token:(NSString *)token {
    [[NSUserDefaults standardUserDefaults] setObject:password forKey:@"password"];
    [[NSUserDefaults standardUserDefaults] setObject:token forKey:@"auth_token"];
}

// Keychain always accessible
- (void)saveToKeychain {
    NSDictionary *query = @{
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAlways
    };
}

@end

@interface PasteboardBugs : NSObject
@end

@implementation PasteboardBugs

// Pasteboard leak - sensitive data
- (void)copyPassword:(NSString *)password {
    [[UIPasteboard generalPasteboard] setString:password];
}

@end

@interface URLSchemeBugs : NSObject
@end

@implementation URLSchemeBugs

// URL Scheme - handler without validation
- (BOOL)application:(UIApplication *)app openURL:(NSURL *)url sourceApplication:(NSString *)source {
    NSString *data = [url absoluteString];
    return YES;
}

// URL Scheme - openURL with dynamic URL
- (void)openExternal:(NSString *)urlString {
    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"myapp://%@", urlString]];
    [[UIApplication sharedApplication] openURL:url];
}

@end

@interface LoggingBugs : NSObject
@end

@implementation LoggingBugs

// NSLog sensitive data
- (void)logCredentials:(NSString *)password token:(NSString *)token {
    NSLog(@"User password: %@", password);
    NSLog(@"Auth token: %@", token);
    NSLog(@"Session cookie: %@", token);
}

// NSLog PII
- (void)logPII:(NSString *)ssn creditCard:(NSString *)cc {
    NSLog(@"SSN: %@, credit_card: %@", ssn, cc);
}

@end

@interface WebViewUnsafe : UIViewController
@end

@implementation WebViewUnsafe

// Deprecated UIWebView
- (void)setup {
    UIWebView *wv = [[UIWebView alloc] init];
    wv.scalesPageToFit = YES;
    wv.javaScriptEnabled = YES;
    wv.allowFileAccessFromFileURLs = YES;
    wv.allowUniversalAccessFromFileURLs = YES;
}

@end

@interface DeprecatedAPIs : NSObject
@end

@implementation DeprecatedAPIs

// Deprecated APIs
- (void)useDeprecated {
    UIAlertView *alert = [[UIAlertView alloc] init];
    UIActionSheet *sheet = [[UIActionSheet alloc] init];
    ABAddressBook ab;
    ALAssetsLibrary *lib = [[ALAssetsLibrary alloc] init];
}

@end

@interface CertPinning : NSObject
@end

@implementation CertPinning

// Missing cert pinning - networking without pinning
- (void)makeRequest {
    NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration defaultSessionConfiguration]];
    // No SecTrustEvaluate or pinnedCertificates
}

@end

@interface FileProtectionBugs : NSObject
@end

@implementation FileProtectionBugs

// File protection missing
- (void)saveFile:(NSData *)data {
    NSFileProtectionNone;
    [[NSFileManager defaultManager] createFileAtPath:@"/tmp/data" contents:data attributes:nil];
}

@end

@interface RetainCycleBugs : NSObject
@property (nonatomic, copy) void (^completionBlock)(void);
@end

@implementation RetainCycleBugs

// Retain cycle - block capturing self
- (void)setupCallback {
    self.completionBlock = ^{
        [self doSomething];
    };
}

@end

@interface IPCBugs : NSObject
@end

@implementation IPCBugs

// Insecure IPC
- (void)setupIPC {
    NSDistributedNotificationCenter *center = [NSDistributedNotificationCenter defaultCenter];
    CFMessagePort port;
}

@end

@interface InputValidation : NSObject
@end

@implementation InputValidation

// Missing input validation - performSelector from string
- (void)handleAction:(NSString *)action {
    SEL selector = NSSelectorFromString(action);
    [self performSelector:selector];
}

// Missing input validation - KVC with user input
- (void)setProperty:(NSString *)key value:(id)value fromUserInput:(NSString *)param {
    [self setValue:value forKeyPath:param];
}

@end
