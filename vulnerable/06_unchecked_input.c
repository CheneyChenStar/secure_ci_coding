/*
 * VULNERABILITY: Unchecked Input (CWE-20)
 *
 * User-supplied input is used in security-sensitive operations without
 * validation of length, character set, or format. This allows:
 * - Buffer overflow from oversized input
 * - Injection attacks via special characters
 * - Logic bypass via unexpected values
 *
 * PRINCIPLE: Validate ALL external input at the boundary:
 * 1. Length check (< MAX)
 * 2. Character allow-list
 * 3. Format/range validation
 *
 * IMPACT: Buffer overflow, authentication bypass, data corruption.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_USERNAME 32
#define USER_DB_SIZE 10

typedef struct {
    char username[MAX_USERNAME];
    char password[64];
    int  role;
} user_t;

static user_t g_users[USER_DB_SIZE];
static int    g_user_count = 0;

static void init_users(void) {
    strcpy(g_users[0].username, "admin");
    strcpy(g_users[0].password, "s3cr3t!");
    g_users[0].role = 0;
    g_user_count = 1;
}

/* VULNERABLE: no input validation */
static int auth_verify_vuln(const char *username, const char *password) {
    for (int i = 0; i < g_user_count; i++) {
        /* BUG: username could be longer than g_users[i].username,
         * or contain NULL bytes, format specifiers, etc. */
        if (strcmp(g_users[i].username, username) == 0 &&
            strcmp(g_users[i].password, password) == 0) {
            return 1;
        }
    }
    return 0;
}

/* FIXED: validates input before processing */
static int auth_verify_fixed(const char *username, const char *password) {
    if (!username || !password) return 0;

    size_t ulen = strlen(username);
    size_t plen = strlen(password);

    /* Length validation */
    if (ulen == 0 || ulen >= MAX_USERNAME) {
        printf("[-] Username length invalid: %zu\n", ulen);
        return 0;
    }
    if (plen == 0 || plen >= 64) {
        printf("[-] Password length invalid\n");
        return 0;
    }

    /* Character allow-list: [a-zA-Z0-9_-.@] */
    for (size_t i = 0; i < ulen; i++) {
        char c = username[i];
        if (!((c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
              c == '_' || c == '-' || c == '.' || c == '@')) {
            printf("[-] Illegal character '%c' (0x%02x) in username\n", c, c);
            return 0;
        }
    }

    /* Now safe to compare */
    for (int i = 0; i < g_user_count; i++) {
        if (strcmp(g_users[i].username, username) == 0 &&
            strcmp(g_users[i].password, password) == 0) {
            return 1;
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    printf("=== CWE-20: Unchecked Input Demo ===\n\n");

    init_users();

    if (argc < 3) {
        printf("Usage: %s <username> <password>\n", argv[0]);
        printf("  Valid:   %s admin s3cr3t!\n", argv[0]);
        printf("  Attack:  %s \"$(python3 -c 'print(\\\"A\\\"*256)')\" test\n", argv[0]);
        printf("  Attack:  %s \"admin\\x00attacker\" test  (NULL byte injection)\n", argv[0]);
        return 0;
    }

    printf("[*] Vulnerable auth (no validation):\n");
    int result_v = auth_verify_vuln(argv[1], argv[2]);
    printf("    Result: %s\n", result_v ? "AUTH OK" : "AUTH FAIL");

    printf("\n[*] Fixed auth (with validation):\n");
    int result_f = auth_verify_fixed(argv[1], argv[2]);
    printf("    Result: %s\n", result_f ? "AUTH OK" : "AUTH FAIL");

    return 0;
}
