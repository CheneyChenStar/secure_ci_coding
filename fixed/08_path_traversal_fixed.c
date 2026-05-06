/*
 * FIXED: Path Traversal (CWE-22)
 *
 * Fixes applied:
 * 1. Reject filenames containing "..", "/", "\\"
 * 2. Use realpath() to resolve canonical path
 * 3. Verify resolved path prefix matches the allowed base directory
 * 4. Length validation on filename
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#define MAX_FILENAME 255

static int file_retrieve_fixed(const char *filename) {
    const char *base_dir = "/tmp/secure_data";
    char full_path[PATH_MAX];
    char resolved[PATH_MAX];

    /* FIX 1: length check */
    size_t fn_len = strlen(filename);
    if (fn_len == 0 || fn_len > MAX_FILENAME) {
        printf("[-] Rejected: filename length %zu out of range\n", fn_len);
        return -1;
    }

    /* FIX 2: reject path traversal characters */
    if (strstr(filename, "..")) {
        printf("[-] Rejected: '..' sequence in filename\n");
        return -1;
    }
    if (strchr(filename, '/') || strchr(filename, '\\')) {
        printf("[-] Rejected: directory separator in filename\n");
        return -1;
    }
    if (filename[0] == '~' || filename[0] == '.') {
        printf("[-] Rejected: filename starts with '%c'\n", filename[0]);
        return -1;
    }

    /* FIX 3: construct and resolve canonical path */
    snprintf(full_path, sizeof(full_path), "%s/%s", base_dir, filename);
    printf("[*] Requested: %s\n", full_path);

    if (realpath(full_path, resolved) == NULL) {
        /* File may not exist yet — resolve parent directory instead */
        char *last_slash = strrchr(full_path, '/');
        if (last_slash) {
            *last_slash = '\0';
            char parent_resolved[PATH_MAX];
            if (realpath(full_path, parent_resolved) != NULL) {
                /* FIX 4: verify parent is under base_dir */
                if (strncmp(parent_resolved, base_dir, strlen(base_dir)) != 0) {
                    printf("[-] Rejected: parent directory outside base\n");
                    printf("    Parent resolved: %s\n", parent_resolved);
                    printf("    Base dir:        %s\n", base_dir);
                    return -1;
                }
                printf("[*] Parent path verified: %s\n", parent_resolved);
            }
            *last_slash = '/';
        }
    } else {
        /* File exists — verify it's under base_dir */
        if (strncmp(resolved, base_dir, strlen(base_dir)) != 0) {
            printf("[-] Rejected: resolved path outside base directory\n");
            printf("    Resolved: %s\n", resolved);
            printf("    Base dir: %s\n", base_dir);
            return -1;
        }
        printf("[*] Canonical path: %s\n", resolved);
    }

    /* FIX 5: proceed with file operation */
    printf("[+] Path validation passed for '%s'\n", filename);

    FILE *fp = fopen(full_path, "r");
    if (!fp) {
        printf("[-] Cannot open: %s (file may not exist)\n", full_path);
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
    printf("=== CWE-22: Path Traversal — FIXED ===\n\n");

    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        printf("  Safe:    %s document.txt\n", argv[0]);
        printf("  Blocked: %s ../../../etc/passwd\n", argv[0]);
        return 0;
    }

    file_retrieve_fixed(argv[1]);

    printf("\n[+] Path traversal prevented.\n");
    printf("    Key fixes:\n");
    printf("    1. Reject '..', '/', '\\\\' in filenames\n");
    printf("    2. Resolve canonical path with realpath()\n");
    printf("    3. Verify prefix matches allowed base directory\n");

    return 0;
}
