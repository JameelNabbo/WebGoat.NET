/*
 * Offensive360 C++ SAST Scanner Test File
 * Additional C++-specific vulnerability patterns.
 */

#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <memory>
#include <thread>
#include <mutex>

/* ============================================================
 * C++ specific: new/delete issues
 * ============================================================ */
void cpp_memory_issues() {
    // Mix of malloc/free with new/delete (undefined behavior)
    int *arr = new int[100];
    // Should use delete[], not free
    // free(arr);  // UB: wrong deallocator

    // VULN: strcpy in C++ code
    char buf[32];
    std::string user_input = "very long string that exceeds buffer size easily";
    strcpy(buf, user_input.c_str());

    // VULN: sprintf in C++
    char msg[64];
    sprintf(msg, "Welcome %s to the application", user_input.c_str());
}

/* ============================================================
 * C++ class with security issues
 * ============================================================ */
class DatabaseConnection {
private:
    // VULN: hardcoded credentials
    const char *password = "db_admin_pass_2026";
    const char *api_key = "AKIAIOSFODNN7EXAMPLE";
    std::string connection_url = "postgres://admin:secret@10.0.0.5:5432/prod";

public:
    void connect() {
        // VULN: system() call
        char cmd[256];
        sprintf(cmd, "mysql -u root -p%s", password);
        system(cmd);
    }

    void query(const char *user_input) {
        // VULN: SQL injection
        char sql[512];
        sprintf(sql, "SELECT * FROM users WHERE email = '%s'", user_input);
    }
};

/* ============================================================
 * Network server with vulnerabilities
 * ============================================================ */
class UnsafeServer {
public:
    void handle_client(int sockfd) {
        char buffer[1024];

        // VULN: recv without return check
        recv(sockfd, buffer, sizeof(buffer), 0);

        // VULN: send without return check
        send(sockfd, "OK", 2, 0);

        // VULN: using received data as command
        system(buffer);
    }

    void process_request(char *request) {
        // VULN: format string
        printf(request);

        // VULN: path traversal
        FILE *f = fopen(request, "r");
        if (f) fclose(f);
    }
};

/* ============================================================
 * Crypto class with weak algorithms
 * ============================================================ */
class WeakCrypto {
public:
    void hash_password(const char *pass) {
        // Would use: MD5(pass, strlen(pass), digest);
        // Would use: SHA1(pass, strlen(pass), digest);
    }

    int generate_session_id() {
        // VULN: weak random
        srand(time(NULL));
        return rand();
    }

    void encrypt_data() {
        // Would use: DES_set_key(...);
        // Would use: RC4_set_key(...);
    }
};

/* ============================================================
 * Thread safety issues in C++
 * ============================================================ */
static int global_counter = 0;
static char global_buffer[512];

class UnsafeThreading {
    static int class_counter;

public:
    void increment() {
        // VULN: no mutex protection
        global_counter++;

        // VULN: strtok not thread safe
        char data[] = "key=value&foo=bar";
        strtok(data, "&");
    }

    void unsafe_time() {
        // VULN: localtime not thread safe
        time_t t = time(NULL);
        struct tm *tm_info = localtime(&t);
        char *time_str = asctime(tm_info);
        printf("Time: %s", time_str);
    }
};

/* ============================================================
 * File operations with issues
 * ============================================================ */
void file_security_issues() {
    // VULN: insecure temp file
    char tmpl[] = "/tmp/app.XXXXXX";
    mktemp(tmpl);

    // VULN: tmpnam race condition
    char *tmp = tmpnam(NULL);

    // VULN: world-writable permissions
    chmod("/var/log/app.log", 0777);

    // VULN: umask zero
    umask(0);

    // VULN: fopen as resource leak
    FILE *log = fopen("/var/log/app.log", "a");
    fprintf(log, "Entry\n");
    // Missing fclose
}

/* ============================================================
 * Privilege and signal issues
 * ============================================================ */
void signal_handler(int sig) {
    // VULN: printf in signal handler (not async-signal-safe)
    printf("Signal received: %d\n", sig);
    // VULN: malloc in signal handler
    char *buf = malloc(64);
    free(buf);
}

void setup() {
    // VULN: signal() instead of sigaction()
    signal(SIGINT, signal_handler);

    // VULN: unchecked setuid
    setuid(0);
    setgid(0);
}

/* ============================================================
 * Array and buffer issues
 * ============================================================ */
void array_issues() {
    int data[5] = {1, 2, 3, 4, 5};

    // VULN: out of bounds
    data[5] = 6;
    data[10] = 11;

    // VULN: strncat off-by-one
    char dest[32] = "prefix";
    strncat(dest, "_suffix_data", sizeof(dest));

    // VULN: strncpy without null termination guarantee
    char dst[8];
    strncpy(dst, "long_string_here", 8);

    // VULN: memcpy with variable size
    int len = 100;
    char src[16] = "hello";
    char target[8];
    memcpy(target, src, len);
}

/* ============================================================
 * Information disclosure and debug
 * ============================================================ */
#ifdef DEBUG
void debug_mode() {
    printf("DEBUG: All passwords dumped\n");
}
#endif

void error_handling() {
    // VULN: perror leaks info
    perror("Database connection failed");

    // VULN: strerror leaks info
    printf("Error: %s\n", strerror(errno));
}

/* ============================================================
 * IoT / Embedded patterns
 * ============================================================ */
#define UART_DEBUG = 1
#define SWD_EN = 0xFF

void iot_config() {
    char *device_id = "DEVICE-001-PROD-LINE-A";
    char *mac_addr = "DE:AD:BE:EF:CA:FE";
}

/* ============================================================
 * Additional patterns
 * ============================================================ */

// VULN: constructor attribute
__attribute__((constructor))
void hidden_init() {
    // Runs before main - potential backdoor
}

// VULN: getenv usage
void config_from_env() {
    char *db_pass = getenv("DB_PASSWORD");
    char cmd[512];
    sprintf(cmd, "connect --password=%s", db_pass);
    system(cmd);

    // VULN: using atoi for env var
    int port = atoi(getenv("PORT"));
}

// VULN: memset before return (compiler may optimize away)
void clear_secret() {
    char key[32];
    // ... use key ...
    memset(key, 0, sizeof(key));
    return;
}

// VULN: goto statement
int process_file(const char *path) {
    FILE *f = NULL;
    char *data = NULL;

    f = fopen(path, "r");
    if (!f) goto cleanup;

    data = (char*)malloc(4096);
    if (!data) goto cleanup;

    fread(data, 1, 4096, f);
    goto cleanup;

cleanup:
    free(data);
    if (f) fclose(f);
    return 0;
}

// Suppressed warnings
#pragma GCC diagnostic ignored "-Wall"

int main() {
    std::cout << "C++ SAST Scanner Test File" << std::endl;
    return 0;
}
