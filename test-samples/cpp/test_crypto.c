/**
 * Test: Cryptographic Vulnerabilities
 * Expected detections: weak crypto, insecure random, hardcoded secrets, OpenSSL misuse
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/des.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

void weak_md5_hash(const char *data) {
    MD5_CTX ctx;
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5_Init(&ctx);         // WEAK CRYPTO: MD5
    MD5_Update(&ctx, data, strlen(data));
    MD5_Final(digest, &ctx);
}

void weak_sha1_hash(const char *data) {
    SHA_CTX ctx;
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1_Init(&ctx);        // WEAK CRYPTO: SHA1
    SHA1_Update(&ctx, data, strlen(data));
    SHA1_Final(digest, &ctx);
}

void weak_des_encrypt(const unsigned char *key, const unsigned char *data) {
    DES_key_schedule ks;
    DES_set_key(key, &ks);  // WEAK CRYPTO: DES
    unsigned char out[8];
    DES_ecb_encrypt(data, out, &ks, DES_ENCRYPT);
}

void insecure_random_numbers() {
    srand(time(NULL));      // INSECURE: predictable seed
    int token = rand();     // INSECURE: not cryptographically secure
    printf("Token: %d\n", token);
}

void hardcoded_credentials() {
    const char *password = "SuperS3cret!Pass";          // HARDCODED SECRET
    const char *api_key = "sk-1234567890abcdef";        // HARDCODED SECRET
    const char *encryption_key = "AES256-KEY-DO-NOT-SHARE"; // HARDCODED SECRET
    const char *auth_token = "Bearer eyJhbGciOi...";    // HARDCODED SECRET
}

SSL_CTX *insecure_ssl_setup() {
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_method());  // DEPRECATED SSL method

    // Disable certificate verification - BAD
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);  // NO CERT VERIFICATION

    // Weak cipher suite
    SSL_CTX_set_cipher_list(ctx, "DES-CBC3-SHA:RC4-SHA:NULL-MD5");  // WEAK CIPHERS

    return ctx;
}

void unencrypted_connection() {
    const char *url = "http://api.example.com/data";     // UNENCRYPTED HTTP
    const char *ftp_url = "ftp://files.example.com/data"; // UNENCRYPTED FTP
    const char *server_ip = "192.168.1.100";              // HARDCODED IP
}

int main() {
    insecure_random_numbers();
    hardcoded_credentials();
    return 0;
}
