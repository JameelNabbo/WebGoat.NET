/**
 * Test: Memory Safety Vulnerabilities
 * Expected detections: use-after-free, double-free, memory leaks, null deref
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void use_after_free() {
    char *ptr = malloc(256);
    strcpy(ptr, "sensitive data");
    free(ptr);
    printf("Data: %s\n", ptr);  // USE AFTER FREE
}

void double_free() {
    int *data = malloc(sizeof(int) * 100);
    data[0] = 42;
    free(data);
    free(data);  // DOUBLE FREE
}

void memory_leak_simple() {
    char *buf = malloc(1024);
    strcpy(buf, "leaked");
    // No free() - MEMORY LEAK
}

char *memory_leak_conditional(int flag) {
    char *a = malloc(64);
    char *b = malloc(64);
    if (flag) {
        free(a);
        return b;
    }
    free(b);
    return a;
    // Both paths return one pointer but leak the other in some flows
}

void null_dereference_unchecked() {
    char *ptr = malloc(1024 * 1024 * 1024);  // 1GB - may fail
    // No NULL check
    strcpy(ptr, "data");  // Potential NULL dereference
}

void null_dereference_checked() {
    char *ptr = malloc(1024);
    if (ptr == NULL) {
        fprintf(stderr, "allocation failed\n");
        return;
    }
    strcpy(ptr, "safe");  // OK: NULL checked
    free(ptr);
}

int *return_local_pointer() {
    int local_var = 42;
    return &local_var;  // RETURN POINTER TO LOCAL
}

void resource_leak() {
    FILE *fp = fopen("/etc/passwd", "r");
    char buf[256];
    fgets(buf, sizeof(buf), fp);
    // No fclose(fp) - RESOURCE LEAK
}

int main() {
    use_after_free();
    double_free();
    memory_leak_simple();
    null_dereference_unchecked();
    return_local_pointer();
    resource_leak();
    return 0;
}
