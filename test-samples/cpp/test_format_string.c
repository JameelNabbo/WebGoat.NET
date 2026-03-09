/**
 * Test: Format String Vulnerabilities
 * Expected detections: printf/fprintf/sprintf/syslog with non-literal format
 */
#include <stdio.h>
#include <syslog.h>
#include <string.h>

void format_string_printf(char *user_input) {
    printf(user_input);  // Format string: non-literal format
}

void format_string_fprintf(FILE *fp, char *msg) {
    fprintf(fp, msg);  // Format string: non-literal format in fprintf
}

void format_string_sprintf(char *buf, char *fmt) {
    sprintf(buf, fmt);  // Format string: non-literal in sprintf
}

void format_string_snprintf(char *buf, size_t len, char *fmt) {
    snprintf(buf, len, fmt);  // Format string: non-literal in snprintf
}

void format_string_syslog(char *user_data) {
    syslog(LOG_INFO, user_data);  // Format string: non-literal in syslog
}

void safe_printf(char *user_input) {
    printf("%s", user_input);  // SAFE: literal format string
}

int main() {
    char input[256];
    fgets(input, sizeof(input), stdin);

    format_string_printf(input);
    format_string_syslog(input);

    char buf[512];
    format_string_sprintf(buf, input);
    format_string_snprintf(buf, sizeof(buf), input);
    return 0;
}
