/*
 * VULNERABILITY: Path Traversal (CWE-22)
 *
 * When a filename from user input is concatenated with a base directory
 * without sanitizing "../" sequences, an attacker can escape the intended
 * directory and access arbitrary files on the system.
 *
 * PRINCIPLE: Always validate paths with realpath() and verify the
 * canonical result stays within the allowed directory. Reject ".." and
 * "/" characters.
 *
 * IMPACT: Arbitrary file read/write/delete — reading /etc/shadow,
 * overwriting ~/.ssh/authorized_keys, etc.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

/* VULNERABLE: direct path concatenation without sanitization */
static int file_retrieve_vuln(const char *filename) {
    char full_path[512];
    const char *base_dir = "/data/files";

    /* BUG: "../" sequences in filename are not filtered */
    snprintf(full_path, sizeof(full_path), "%s/%s", base_dir, filename);

    printf("[*] Attempting to open: %s\n", full_path);

    FILE *fp = fopen(full_path, "r");
    if (!fp) {
        printf("[-] Cannot open: %s\n", full_path);
        return -1;
    }

    char buf[256];
    if (fgets(buf, sizeof(buf), fp)) {
        printf("[+] First line: %s", buf);
    }
    fclose(fp);
    return 0;
}

/* FIXED: validates the canonical path */
static int file_retrieve_fixed(const char *filename) {
    char full_path[512];
    const char *base_dir = "/tmp/secure_data";

    /* Reject obvious traversal patterns */
    if (strstr(filename, "..") ||
        strchr(filename, '/') ||
        strchr(filename, '\\')) {
        printf("[-] Blocked: traversal attempt detected in '%s'\n", filename);
        return -1;
    }

    snprintf(full_path, sizeof(full_path), "%s/%s", base_dir, filename);

    /* Resolve canonical path */
    char resolved[PATH_MAX];
    if (realpath(full_path, resolved) == NULL) {
        printf("[-] Cannot resolve path: %s\n", full_path);
        return -1;
    }

    /* Verify resolved path stays within base_dir */
    if (strncmp(resolved, base_dir, strlen(base_dir)) != 0) {
        printf("[-] Blocked: '%s' resolves outside base directory\n", filename);
        printf("    Resolved: %s\n", resolved);
        return -1;
    }

    printf("[*] Resolved path: %s\n", resolved);
    FILE *fp = fopen(resolved, "r");
    if (!fp) {
        printf("[-] Cannot open: %s\n", resolved);
        return -1;
    }

    char buf[256];
    if (fgets(buf, sizeof(buf), fp)) {
        printf("[+] First line: %s", buf);
    }
    fclose(fp);
    return 0;
}

int main(int argc, char *argv[]) {
    printf("=== CWE-22: Path Traversal Demo ===\n\n");

    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        printf("\n  Normal:   %s document.txt\n", argv[0]);
        printf("  Exploit:  %s ../../../etc/passwd\n", argv[0]);
        printf("  Exploit:  %s ../../../etc/shadow\n", argv[0]);
        printf("  Exploit:  %s ..%%2f..%%2f..%%2fetc%%2fpasswd  (encoded)\n", argv[0]);
        return 0;
    }

    printf("--- Vulnerable (no sanitization) ---\n");
    file_retrieve_vuln(argv[1]);

    printf("\n--- Fixed (canonical path check) ---\n");
    file_retrieve_fixed(argv[1]);

    return 0;
}
