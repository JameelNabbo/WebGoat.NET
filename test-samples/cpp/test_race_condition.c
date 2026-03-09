/**
 * Test: Race Conditions, Signal Safety, Thread Safety, Privilege Issues
 * Expected detections: TOCTOU, signal handler unsafe, non-reentrant, privilege drop
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>

/* ---- TOCTOU Race Conditions ---- */

void toctou_access_open(const char *path) {
    if (access(path, W_OK) == 0) {
        // Race window: file can be swapped via symlink
        int fd = open(path, O_WRONLY);  // TOCTOU
        if (fd >= 0) {
            write(fd, "data", 4);
            close(fd);
        }
    }
}

void toctou_stat_open(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (st.st_size < 1024) {
            FILE *fp = fopen(path, "r");  // TOCTOU: stat then open
            if (fp) fclose(fp);
        }
    }
}

/* ---- Signal Handler Safety ---- */

volatile sig_atomic_t got_signal = 0;

void unsafe_signal_handler(int signo) {
    printf("Caught signal %d\n", signo);     // UNSAFE: printf in signal handler
    char *buf = malloc(256);                  // UNSAFE: malloc in signal handler
    if (buf) {
        sprintf(buf, "Signal: %d", signo);
        free(buf);                            // UNSAFE: free in signal handler
    }
    syslog(LOG_INFO, "Signal caught: %d", signo); // UNSAFE: syslog in handler
}

void setup_signal_handler() {
    signal(SIGINT, unsafe_signal_handler);
    signal(SIGTERM, unsafe_signal_handler);
}

/* ---- Thread Safety ---- */

int shared_counter = 0;  // Global without mutex

void *thread_func(void *arg) {
    char *time_str = ctime(NULL);       // NON-REENTRANT: ctime
    char *tok = strtok(time_str, " ");  // NON-REENTRANT: strtok
    char *host = gethostbyname("example.com"); // NON-REENTRANT: gethostbyname
    char *err = strerror(42);           // NON-REENTRANT: strerror
    shared_counter++;                    // RACE: no mutex
    return NULL;
}

void threaded_code() {
    pthread_t t1, t2;
    pthread_create(&t1, NULL, thread_func, NULL);
    pthread_create(&t2, NULL, thread_func, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
}

/* ---- Privilege Escalation ---- */

void bad_privilege_drop() {
    setuid(0);      // Escalate to root
    // Do privileged operation
    setgid(1000);   // WRONG ORDER: gid after uid
    setuid(1000);
}

void unchecked_privilege_drop() {
    setuid(1000);   // UNCHECKED return
    // May still be root if setuid failed!
}

/* ---- Insecure File Operations ---- */

void insecure_temp_file() {
    char *tmp = mktemp("/tmp/myapp_XXXXXX");  // INSECURE: mktemp
    FILE *fp = fopen(tmp, "w");
    if (fp) {
        fprintf(fp, "sensitive data");
        fclose(fp);
    }
    chmod(tmp, 0777);  // WORLD WRITABLE
}

int main() {
    setup_signal_handler();
    threaded_code();
    toctou_access_open("/tmp/testfile");
    bad_privilege_drop();
    insecure_temp_file();
    return 0;
}
