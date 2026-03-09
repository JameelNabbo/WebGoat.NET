//
//  VulnerableViewController.m
//  InsecureApp
//
//  Intentionally vulnerable Objective-C code for SAST scanner testing
//

#import <UIKit/UIKit.h>
#import <sqlite3.h>
#import <CommonCrypto/CommonCrypto.h>
#import <Security/Security.h>

#define API_KEY @"sk-live-abc123def456ghi789jkl012mno345"
#define SECRET_TOKEN @"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"

@interface VulnerableViewController : UIViewController
@property (nonatomic, strong) NSMutableArray *sensitiveData;
@property (nonatomic, strong) NSString *userToken;
@end

@implementation VulnerableViewController

// SQL Injection - sqlite3_exec with format string
- (void)searchUser:(NSString *)username {
    sqlite3 *db;
    NSString *query = [NSString stringWithFormat:@"SELECT * FROM users WHERE name = '%@'", username];
    char *errMsg;
    sqlite3_exec(db, [query UTF8String], NULL, NULL, &errMsg);
}

// SQL Injection - NSPredicate format injection
- (void)filterData:(NSString *)userInput {
    NSPredicate *predicate = [NSPredicate predicateWithFormat:userInput];
    NSArray *filtered = [self.sensitiveData filteredArrayUsingPredicate:predicate];
}

// Command Injection - system()
- (void)executeCommand:(NSString *)cmd {
    NSString *fullCmd = [NSString stringWithFormat:@"/bin/sh -c %@", cmd];
    system([fullCmd UTF8String]);
}

// Command Injection - NSTask
- (void)runTask:(NSString *)argument {
    NSTask *task = [[NSTask alloc] init];
    [task setLaunchPath:@"/usr/bin/env"];
    NSString *formatted = [NSString stringWithFormat:@"echo %@", argument];
    [task setArguments:@[formatted]];
    [task launch];
}

// XSS - UIWebView loadHTMLString
- (void)displayContent:(NSString *)userInput {
    UIWebView *webView = [[UIWebView alloc] init];
    NSString *html = [NSString stringWithFormat:@"<html><body>%@</body></html>", userInput];
    [webView loadHTMLString:html baseURL:nil];
}

// XSS - evaluateJavaScript
- (void)executeJS:(NSString *)userInput {
    WKWebView *webView = [[WKWebView alloc] init];
    NSString *js = [NSString stringWithFormat:@"document.title = '%@'", userInput];
    [webView evaluateJavaScript:js completionHandler:nil];
}

// Insecure Data Storage - NSUserDefaults
- (void)storeCredentials:(NSString *)password token:(NSString *)token {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    [defaults setObject:password forKey:@"user_password"];
    [defaults setObject:token forKey:@"auth_token"];
    [defaults synchronize];
}

// Insecure Data Storage - plist
- (void)saveToPlist:(NSDictionary *)data {
    NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/secrets.plist"];
    [data writeToFile:path atomically:YES];
}

// Insecure Communication - ATS disabled
- (void)configureATS {
    // Info.plist would have:
    // NSAllowsArbitraryLoads = YES
    NSString *setting = @"NSAllowsArbitraryLoads";
    BOOL value = YES;
}

// Insecure Communication - HTTP URL
- (void)fetchData {
    NSURL *url = [NSURL URLWithString:@"http://api.example.com/data"];
    NSURLSession *session = [NSURLSession sharedSession];
    // No certificate pinning
}

// Format String vulnerability
- (void)logMessage:(NSString *)userInput {
    NSLog(userInput);  // Format string vuln - should be NSLog(@"%@", userInput)
}

// Buffer Overflow
- (void)processBuffer:(const char *)input {
    char buffer[64];
    strcpy(buffer, input);      // No bounds check
    strcat(buffer, " suffix");  // Can overflow
    sprintf(buffer, "%s", input); // Unsafe
    gets(buffer);                // Never safe
}

// Memory Management - no [super dealloc]
- (void)dealloc {
    [_sensitiveData release];
    [_userToken release];
    // Missing [super dealloc]
}

// Hardcoded Secrets
- (void)connectToService {
    NSString *password = @"SuperSecretP@ssw0rd!";
    NSString *apiKey = @"AKIAIOSFODNN7EXAMPLE";
    NSString *secretKey = @"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
}

// Weak Crypto - MD5
- (NSString *)hashPassword:(NSString *)password {
    const char *cStr = [password UTF8String];
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5(cStr, (CC_LONG)strlen(cStr), digest);

    NSMutableString *output = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
        [output appendFormat:@"%02x", digest[i]];
    }
    return output;
}

// Weak Crypto - DES
- (NSData *)encryptData:(NSData *)data withKey:(NSData *)key {
    size_t outLength;
    NSMutableData *cipherData = [NSMutableData dataWithLength:data.length + kCCBlockSizeDES];
    CCCrypt(kCCEncrypt, kCCAlgorithmDES, kCCOptionECBMode,
            key.bytes, key.length, NULL,
            data.bytes, data.length,
            cipherData.mutableBytes, cipherData.length, &outLength);
    return cipherData;
}

// Insecure Random
- (int)generateToken {
    srand(time(NULL));
    return rand() % 1000000;
}

// iOS-specific - UIPasteboard
- (void)copyPassword:(NSString *)password {
    UIPasteboard *pb = [UIPasteboard generalPasteboard];
    pb.string = password;
}

// iOS-specific - keyboard cache not disabled
- (void)setupTextField {
    UITextField *field = [[UITextField alloc] init];
    // Missing secureTextEntry and autocorrectionType settings
}

// Keychain misuse
- (void)storeInKeychain:(NSString *)secret {
    NSDictionary *attributes = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAlways,
        (__bridge id)kSecValueData: [secret dataUsingEncoding:NSUTF8StringEncoding],
    };
    SecItemAdd((__bridge CFDictionaryRef)attributes, NULL);
}

// SSL pinning bypassed
- (void)setupConnection {
    // Trust all certificates
    [self allowsAnyHTTPSCertificateForHost:@"api.example.com"];
}

// Information Disclosure - NSLog with sensitive data
- (void)loginUser:(NSString *)username password:(NSString *)password {
    NSLog(@"Login attempt: user=%@, password=%@", username, password);
}

// Deep link without validation
- (BOOL)application:(UIApplication *)app openURL:(NSURL *)url options:(NSDictionary *)options {
    // No scheme/host validation
    [self handleOpenURL:url];
    return YES;
}

// Race condition - nonatomic mutable property defined in interface

// URL Scheme
- (void)launchExternalApp:(NSURL *)url {
    [[UIApplication sharedApplication] openURL:url];
}

// Deprecated API
- (void)showAlert:(NSString *)msg {
    UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"Alert"
                                                    message:msg
                                                   delegate:nil
                                          cancelButtonTitle:@"OK"
                                          otherButtonTitles:nil];
    [alert show];
}

// Jailbreak detection - weak
- (BOOL)isJailbroken {
    return [[NSFileManager defaultManager] fileExistsAtPath:@"/Applications/Cydia.app"];
}

@end
