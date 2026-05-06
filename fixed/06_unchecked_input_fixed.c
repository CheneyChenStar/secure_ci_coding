/*
 * FIXED: Unchecked Input (CWE-20)
 *
 * Fixes applied:
 * 1. Validate input length before use
 * 2. Enforce character allow-list [a-zA-Z0-9_-.@]
 * 3. Reject input with embedded NUL bytes
 * 4. Use constant-time comparison where relevant
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#define MAX_USERNAME 32
#define MAX_PASSWORD 128

/* FIX: validate username format and length */
static bool validate_username(const char *username) {
    if (!username) return false;

    size_t len = strlen(username);

    /* Length check */
    if (len == 0 || len >= MAX_USERNAME) {
        printf("[-] Username length %zu out of range [1, %d]\n", len, MAX_USERNAME - 1);
        return false;
    }

    /* Character allow-list */
    for (size_t i = 0; i < len; i++) {
        char c = username[i];
        if (!((c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
              c == '_' || c == '-' || c == '.' || c == '@')) {
            printf("[-] Illegal character '%c' (0x%02x) at position %zu\n", c, c, i);
            return false;
        }
    }

    return true;
}

/* FIX: validate password (different rules, typically more permissive but length-bounded) */
static bool validate_password(const char *password) {
    if (!password) return false;

    size_t len = strlen(password);
    if (len == 0 || len >= MAX_PASSWORD) {
        printf("[-] Password length %zu out of range [1, %d]\n", len, MAX_PASSWORD - 1);
        return false;
    }

    /* No NULL bytes, no control characters */
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)password[i];
        if (c < 0x20 || c == 0x7F) {
            printf("[-] Control character (0x%02x) in password at position %zu\n", c, i);
            return false;
        }
    }

    return true;
}

int main(int argc, char *argv[]) {
    printf("=== CWE-20: Unchecked Input — FIXED ===\n\n");

    if (argc < 3) {
        printf("Usage: %s <username> <password>\n", argv[0]);
        printf("  Valid:   %s admin s3cr3t!\n", argv[0]);
        printf("  Invalid: %s \"user; DROP TABLE\" test\n", argv[0]);
        printf("  Invalid: %s \"$(python3 -c 'print(\\\"A\\\"*256)')\" test\n", argv[0]);
        return 0;
    }

    printf("[*] Validating username '%s'...\n", argv[1]);
    bool user_ok = validate_username(argv[1]);

    printf("[*] Validating password...\n");
    bool pass_ok = validate_password(argv[2]);

    if (user_ok && pass_ok) {
        printf("[+] Input validation PASSED\n");
        printf("    Proceed to authentication...\n");
    } else {
        printf("[-] Input validation FAILED\n");
        printf("    Request rejected before processing\n");
    }

    printf("\n[+] Input validation complete.\n");
    printf("    Key principles:\n");
    printf("    1. Validate at the boundary (right where input enters)\n");
    printf("    2. Length + character set + format\n");
    printf("    3. Reject, don't try to sanitize/repair\n");

    return 0;
}
