/**
 * Test: Buffer Overflow Vulnerabilities
 * Expected detections: strcpy, strcat, sprintf, gets, scanf %s, memcpy mismatch
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void unsafe_strcpy(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // Buffer overflow: no bounds check
    printf("Copied: %s\n", buffer);
}

void unsafe_strcat() {
    char dest[32] = "Hello ";
    char *src = "This is a very long string that will overflow the buffer easily";
    strcat(dest, src);  // Buffer overflow: no bounds check
}

void unsafe_sprintf(const char *user, int id) {
    char query[64];
    sprintf(query, "SELECT * FROM users WHERE name='%s' AND id=%d", user, id);  // Overflow
    printf("%s\n", query);
}

void unsafe_gets() {
    char buf[128];
    printf("Enter input: ");
    gets(buf);  // BANNED: always overflows
}

void unsafe_scanf() {
    char name[32];
    scanf("%s", name);  // No width limit
}

void memcpy_mismatch() {
    char src[256];
    char dst[64];
    memset(src, 'A', sizeof(src));
    memcpy(dst, src, sizeof(src));  // sizeof mismatch: copies 256 into 64-byte buffer
}

int main() {
    unsafe_strcpy("test");
    unsafe_strcat();
    unsafe_sprintf("admin", 1);
    unsafe_gets();
    unsafe_scanf();
    memcpy_mismatch();
    return 0;
}
