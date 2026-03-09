/**
 * Test: Injection Vulnerabilities
 * Expected detections: command injection, SQL injection, path traversal
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

void command_injection_system(char *filename) {
    char cmd[512];
    sprintf(cmd, "cat %s", filename);
    system(cmd);  // COMMAND INJECTION: user-controlled argument
}

void command_injection_popen(char *host) {
    char cmd[256];
    sprintf(cmd, "ping -c 1 %s", host);
    FILE *fp = popen(cmd, "r");  // COMMAND INJECTION
    pclose(fp);
}

void command_injection_exec(char *arg) {
    char cmd[256];
    sprintf(cmd, "/usr/bin/tool %s", arg);
    execl("/bin/sh", "sh", "-c", cmd, NULL);  // COMMAND INJECTION
}

void sql_injection(sqlite3 *db, char *username) {
    char query[1024];
    sprintf(query, "SELECT * FROM users WHERE name='%s'", username);
    sqlite3_exec(db, query, NULL, NULL, NULL);  // SQL INJECTION
}

void sql_injection_mysql(void *conn, char *input) {
    char query[512];
    sprintf(query, "DELETE FROM sessions WHERE token='%s'", input);
    mysql_query(conn, query);  // SQL INJECTION
}

void path_traversal_fopen(char *user_path) {
    FILE *fp = fopen(user_path, "r");  // PATH TRAVERSAL: user-controlled path
    if (fp) {
        char buf[4096];
        fread(buf, 1, sizeof(buf), fp);
        fclose(fp);
    }
}

void path_traversal_constructed(char *filename) {
    char path[256];
    sprintf(path, "/var/data/%s", filename);  // ../../../etc/passwd
    FILE *fp = fopen(path, "r");  // PATH TRAVERSAL
    if (fp) fclose(fp);
}

void toctou_access_open(const char *filepath) {
    if (access(filepath, R_OK) == 0) {
        // Time gap - file can be swapped via symlink
        FILE *fp = fopen(filepath, "r");  // TOCTOU RACE CONDITION
        if (fp) fclose(fp);
    }
}

int main() {
    command_injection_system("test.txt");
    return 0;
}
