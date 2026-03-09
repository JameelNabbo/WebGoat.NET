/*
 * Offensive360 C/C++ SAST Scanner - Comprehensive Test File
 * Contains deliberately vulnerable code covering ALL 30+ vulnerability categories.
 * DO NOT USE IN PRODUCTION - This is for scanner testing only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

/* ============================================================
 * 1. BUFFER OVERFLOW - strcpy, strcat, sprintf, gets, scanf
 * ============================================================ */
void buffer_overflow_examples() {
    char small_buf[16];
    char large_input[256] = "This is a very long string that will overflow the small buffer when copied";

    // VULN: strcpy without bounds check
    strcpy(small_buf, large_input);

    // VULN: strcat without bounds check
    strcat(small_buf, " more data appended here");

    // VULN: sprintf without bounds check
    sprintf(small_buf, "User: %s, Age: %d", large_input, 25);

    // VULN: vsprintf without bounds check (would need va_list)
    // vsprintf(small_buf, fmt, args);

    // VULN: gets - absolutely never safe
    char user_input[64];
    gets(user_input);

    // VULN: scanf %s without width limit
    char name[32];
    scanf("%s", name);

    // VULN: sscanf without width
    char src[] = "hello world";
    char dst[8];
    sscanf(src, "%s", dst);

    // VULN: wcscpy without bounds
    // wchar_t wbuf[16];
    // wcscpy(wbuf, L"this is too long for the buffer");
}

/* ============================================================
 * 2. FORMAT STRING VULNERABILITIES
 * ============================================================ */
void format_string_examples(char *user_data) {
    // VULN: user-controlled format string
    printf(user_data);

    // VULN: fprintf with variable format
    fprintf(stderr, user_data);

    // SAFE: using %s format literal
    printf("%s", user_data);
}

/* ============================================================
 * 3. INTEGER OVERFLOW
 * ============================================================ */
void integer_overflow_examples(int count) {
    // VULN: integer overflow in malloc size
    int *arr = malloc(count * sizeof(int));

    // VULN: atoi - no error checking, UB on overflow
    char *num_str = "99999999999999999";
    int value = atoi(num_str);

    // VULN: atol - same issue
    long lval = atol(num_str);

    // VULN: atof - no error checking
    double dval = atof("not_a_number");
}

/* ============================================================
 * 4. USE AFTER FREE
 * ============================================================ */
void use_after_free_example() {
    char *buffer = malloc(128);
    strcpy(buffer, "sensitive data");

    free(buffer);
    // VULN: using buffer after free
    printf("Data: %s\n", buffer);
    buffer[0] = 'A';
}

/* ============================================================
 * 5. DOUBLE FREE
 * ============================================================ */
void double_free_example() {
    char *ptr = malloc(64);
    strcpy(ptr, "hello");

    free(ptr);
    // VULN: freeing same pointer twice
    free(ptr);
}

/* ============================================================
 * 6. NULL POINTER DEREFERENCE
 * ============================================================ */
void null_deref_example(size_t size) {
    // VULN: malloc without NULL check
    char *data = malloc(size);
    memcpy(data, "hello", 5);

    int *numbers = calloc(100, sizeof(int));
    numbers[0] = 42;
}

/* ============================================================
 * 7. MEMORY LEAKS
 * ============================================================ */
void memory_leak_example() {
    // VULN: malloc without free
    char *leaked = malloc(1024);
    strcpy(leaked, "this memory is never freed");

    // Another leak
    int *data = calloc(256, sizeof(int));
    data[0] = 1;
    // function returns without freeing
}

/* ============================================================
 * 8. STACK OVERFLOW
 * ============================================================ */
void stack_overflow_examples(int user_size) {
    // VULN: alloca with potentially large/user-controlled size
    char *stack_buf = alloca(user_size);

    // VULN: large stack allocation
    char huge_buffer[100000];

    // VULN: variable-length array
    int dynamic_array[user_size];

    // VULN: recursive without depth limit
}

int recursive_parse(char *data) {
    if (*data == '\0') return 0;
    return 1 + recursive_parse(data + 1);
}

/* ============================================================
 * 9. COMMAND INJECTION
 * ============================================================ */
void command_injection_examples(char *user_input) {
    char cmd[256];

    // VULN: system() with user input
    sprintf(cmd, "ls %s", user_input);
    system(cmd);

    // VULN: popen() with user input
    FILE *fp = popen(cmd, "r");
    pclose(fp);

    // VULN: exec family
    execlp("sh", "sh", "-c", user_input, NULL);
    execvp("/bin/sh", NULL);
}

/* ============================================================
 * 10. SQL INJECTION
 * ============================================================ */
void sql_injection_example(char *username) {
    char query[512];
    // VULN: SQL built with sprintf
    sprintf(query, "SELECT * FROM users WHERE name = '%s'", username);
    // execute(query);

    // VULN: SQL with strcat
    char sql[256] = "DELETE FROM sessions WHERE user = '";
    strcat(sql, username);
}

/* ============================================================
 * 11. PATH TRAVERSAL
 * ============================================================ */
void path_traversal_example(char *filename) {
    // VULN: opening file from user input without validation
    FILE *f = fopen(filename, "r");

    // VULN: literal directory traversal
    FILE *g = fopen("../../etc/passwd", "r");

    // VULN: using argv directly
    // FILE *h = fopen(argv[1], "r");
}

/* ============================================================
 * 12. RACE CONDITIONS (TOCTOU)
 * ============================================================ */
void toctou_example(const char *filename) {
    // VULN: TOCTOU - check then use
    if (access(filename, R_OK) == 0) {
        // Attacker can swap file between access() and fopen()
        FILE *f = fopen(filename, "r");
        fclose(f);
    }
}

/* ============================================================
 * 13. HARDCODED SECRETS
 * ============================================================ */
void hardcoded_secrets() {
    // VULN: hardcoded password
    char *password = "SuperSecret123!";
    char *api_key = "sk-1234567890abcdef";
    char *token = "eyJhbGciOiJIUzI1NiJ9.secret";
    char *secret_key = "my_application_secret_key_do_not_share";

    // VULN: hardcoded IP
    char *server = "192.168.1.100";
    char *db_host = "10.0.0.50";

    // VULN: credentials in URL
    char *db_url = "mysql://admin:password123@10.0.0.50:3306/mydb";
    char *api_url = "https://user:pass@api.example.com/v1";
}

/* ============================================================
 * 14. WEAK CRYPTOGRAPHY
 * ============================================================ */
void weak_crypto_examples() {
    // These would need OpenSSL headers, but the scanner checks for function names:
    // VULN: MD5 (broken hash)
    // MD5_Init(&ctx);
    // MD5(data, len, digest);

    // VULN: SHA1 (deprecated)
    // SHA1(data, len, digest);

    // VULN: DES (broken cipher)
    // DES_set_key(&key, &schedule);
    // DES_ecb_encrypt(&input, &output, &schedule, DES_ENCRYPT);

    // VULN: RC4 (broken stream cipher)
    // RC4_set_key(&key, len, key_data);
}

/* ============================================================
 * 15. INSECURE RANDOM
 * ============================================================ */
void insecure_random_examples() {
    // VULN: srand/rand for security
    srand(42);
    int session_token = rand();

    // VULN: random() also weak
    long nonce = random();
}

/* ============================================================
 * 16. DANGEROUS FUNCTIONS (misc)
 * ============================================================ */
void dangerous_function_examples() {
    // VULN: mktemp - predictable temp file
    char template[] = "/tmp/myapp.XXXXXX";
    mktemp(template);

    // VULN: tmpnam - race condition
    char *tmp = tmpnam(NULL);

    // VULN: tempnam - same issues
    char *tmp2 = tempnam("/tmp", "pfx");

    // VULN: realloc without saving original pointer
    char *buf = malloc(64);
    buf = realloc(buf, 128);
}

/* ============================================================
 * 17. UNINITIALIZED VARIABLES
 * ============================================================ */
void uninitialized_var_examples() {
    int *ptr;
    // VULN: using ptr before initialization
    // *ptr = 42;  // Would crash

    char *data;
    // VULN: uninitialized pointer
    // printf("%s", data);  // UB
}

/* ============================================================
 * 18. ARRAY OUT OF BOUNDS
 * ============================================================ */
void array_bounds_example() {
    int arr[10];
    arr[0] = 1;
    arr[9] = 10;

    // VULN: out of bounds access
    arr[10] = 11;
    arr[15] = 16;
}

/* ============================================================
 * 19. TYPE CONFUSION
 * ============================================================ */
void type_confusion_example(void *arg) {
    // VULN: unsafe void* cast without verification
    struct user_data {
        int id;
        char name[64];
    };
    struct user_data *user = (struct user_data *)arg;
}

/* ============================================================
 * 20. SIGNAL HANDLER ISSUES
 * ============================================================ */
void unsafe_signal_handler(int sig) {
    // VULN: printf is not async-signal-safe
    printf("Caught signal %d\n", sig);
    // VULN: malloc is not async-signal-safe
    char *buf = malloc(64);
    free(buf);
}

void setup_signals() {
    // VULN: using signal() instead of sigaction()
    signal(SIGINT, unsafe_signal_handler);
    signal(SIGTERM, unsafe_signal_handler);
}

/* ============================================================
 * 21. CRYPTOGRAPHIC ISSUES
 * ============================================================ */
void crypto_issues() {
    // VULN: SSL verification disabled
    // SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    // VULN: Weak RSA key
    // RSA_generate_key(1024, RSA_F4, NULL, NULL);

    // VULN: Deprecated TLS versions
    // SSLv3_method();
    // TLSv1_method();
}

/* ============================================================
 * 22. FILE PERMISSION ISSUES
 * ============================================================ */
void file_permission_examples() {
    // VULN: world-writable
    chmod("/tmp/secrets.txt", 0777);

    // VULN: world-writable on create
    int fd = open("/tmp/data.txt", O_CREAT | O_WRONLY, 0766);

    // VULN: umask set to 0
    umask(0);

    close(fd);
}

/* ============================================================
 * 23. PRIVILEGE ESCALATION
 * ============================================================ */
void privilege_examples() {
    // VULN: setuid without return check
    setuid(0);
    setgid(0);
    seteuid(1000);

    // SAFE: with check
    if (setuid(1000) != 0) {
        perror("setuid failed");
        exit(1);
    }
}

/* ============================================================
 * 24. INFORMATION DISCLOSURE
 * ============================================================ */
void info_disclosure_examples() {
    FILE *f = fopen("/etc/secret", "r");
    if (!f) {
        // VULN: detailed error to user
        perror("Failed to open secret file");
    }

    // VULN: strerror in response
    char *err = strerror(errno);
}

/* ============================================================
 * 25. MISSING INPUT VALIDATION
 * ============================================================ */
void input_validation_examples(int sockfd) {
    char buf[1024];

    // VULN: recv without checking return value
    recv(sockfd, buf, sizeof(buf), 0);

    // VULN: write without checking return
    write(sockfd, buf, strlen(buf));

    // VULN: send without checking return
    send(sockfd, "response", 8, 0);
}

/* ============================================================
 * 26. UNSAFE STRING OPERATIONS
 * ============================================================ */
void unsafe_string_examples() {
    char dest[64] = "hello";

    // VULN: strncat with sizeof(dest) - off by one
    strncat(dest, " world", sizeof(dest));

    // VULN: strncpy may not null-terminate
    char dst[16];
    strncpy(dst, "this is a long string", 16);
    // Missing: dst[15] = '\0';
}

/* ============================================================
 * 27. THREAD SAFETY
 * ============================================================ */
static int shared_counter = 0;
static char shared_buffer[256];

void *thread_func(void *arg) {
    // VULN: accessing shared state without mutex
    shared_counter++;
    strcpy(shared_buffer, "thread data");

    // VULN: strtok is not thread-safe
    char data[] = "a,b,c,d";
    char *tok = strtok(data, ",");

    // VULN: non-reentrant functions
    char *timestr = ctime(NULL);
    struct tm *tm = localtime(NULL);
    char *asc = asctime(tm);
    struct tm *gm = gmtime(NULL);

    return NULL;
}

/* ============================================================
 * 28. COMPILER WARNINGS (suppressed)
 * ============================================================ */
#pragma warning(disable: 4996)
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

/* ============================================================
 * 29. RESOURCE LEAKS
 * ============================================================ */
void resource_leak_examples() {
    // VULN: fopen without fclose
    FILE *f = fopen("/tmp/test.txt", "r");
    // No fclose(f) on error path

    // VULN: socket without close
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    // forgot close(sock)
}

/* ============================================================
 * 30. EMBEDDED/IoT SPECIFIC
 * ============================================================ */
#define UART_DEBUG = 1
#define JTAG_EN = 0x01
#define SERIAL_DEBUG = true

void iot_examples() {
    // VULN: hardcoded MAC address
    char *mac_addr = "AA:BB:CC:DD:EE:FF";
    char *serial_number = "SN-12345-ABCDE";
    char *device_id = "DEV-001-FACTORY";
}

/* ============================================================
 * 31. MEMSET FOR SENSITIVE DATA
 * ============================================================ */
void sensitive_data_clearing() {
    char password[64];
    // ... use password ...

    // VULN: memset may be optimized away before free/return
    memset(password, 0, sizeof(password));
    return;
}

/* ============================================================
 * 32. ENVIRONMENT MANIPULATION
 * ============================================================ */
void env_examples() {
    // VULN: getenv without validation
    char *path = getenv("PATH");
    char *home = getenv("HOME");

    // Using env var in dangerous context
    char cmd[256];
    sprintf(cmd, "%s/script.sh", home);
    system(cmd);
}

/* ============================================================
 * 33. DEBUG CODE
 * ============================================================ */
#ifdef DEBUG
void debug_backdoor() {
    // This code should not be in production
    printf("DEBUG: Admin bypass enabled\n");
    setuid(0);
}
#endif

#ifndef NDEBUG
void debug_logging() {
    printf("DEBUG: Dumping all memory...\n");
}
#endif

/* ============================================================
 * 34. GOTO USAGE
 * ============================================================ */
int goto_example(const char *filename) {
    FILE *f = NULL;
    char *buf = NULL;

    f = fopen(filename, "r");
    if (!f) goto error;

    buf = malloc(1024);
    if (!buf) goto error;

    // ... use f and buf ...

    free(buf);
    fclose(f);
    return 0;

error:
    if (buf) free(buf);
    if (f) fclose(f);
    return -1;
}

/* ============================================================
 * 35. CONSTRUCTOR ATTRIBUTE
 * ============================================================ */
__attribute__((constructor))
void auto_init() {
    // VULN: runs before main - verify security
    printf("Auto-initializing...\n");
}

/* ============================================================
 * 36. LOOP WITH EXTERNAL BOUNDS
 * ============================================================ */
struct packet_header {
    int length;
    int type;
};

void process_packet(struct packet_header *header, char *data) {
    // VULN: loop bounded by untrusted network data
    for (int i = 0; i < header->length; i++) {
        // Process data[i]
    }
}

/* ============================================================
 * MAIN
 * ============================================================ */
int main(int argc, char *argv[]) {
    printf("C/C++ SAST Scanner Test - Vulnerable Code Samples\n");

    // Exercise some of the vulnerable functions
    buffer_overflow_examples();
    format_string_examples("user input %x %x %n");
    integer_overflow_examples(1000000);
    hardcoded_secrets();
    setup_signals();

    return 0;
}
