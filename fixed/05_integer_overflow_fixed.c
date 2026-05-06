/*
 * FIXED: Integer Overflow (CWE-190)
 *
 * Fixes applied:
 * 1. Check for overflow BEFORE performing arithmetic
 * 2. Guard: if (data_len > SIZE_MAX - 1) reject
 * 3. Set maximum payload size limit
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PAYLOAD (16 * 1024 * 1024)  /* 16 MB */

static int file_store_fixed(const char *data, size_t data_len) {
    printf("[*] file_store(data_len=%zu)\n", data_len);

    /* FIX 1: reject zero-length data */
    if (data_len == 0) {
        printf("[-] Rejected: zero-length data\n");
        return -1;
    }

    /* FIX 2: enforce maximum size */
    if (data_len > MAX_PAYLOAD) {
        printf("[-] Rejected: data_len %zu exceeds max %zu\n", data_len, (size_t)MAX_PAYLOAD);
        return -1;
    }

    /* FIX 3: check for integer overflow BEFORE arithmetic
     *
     * Pattern: if (a > MAX_TYPE - b) then a + b will overflow
     * Here: if (data_len > SIZE_MAX - 1) then data_len + 1 overflows
     *
     * Since data_len <= MAX_PAYLOAD << SIZE_MAX, this always passes,
     * but the check is still good practice for defense-in-depth.
     */
    if (data_len > SIZE_MAX - 1) {
        printf("[-] Rejected: data_len %zu would cause integer overflow\n", data_len);
        return -1;
    }

    /* Safe: no overflow possible */
    size_t alloc_size = data_len + 1;
    char *buffer = malloc(alloc_size);

    if (!buffer) {
        printf("[-] malloc(%zu) failed\n", alloc_size);
        return -1;
    }

    printf("[*] Allocated %zu bytes at %p\n", alloc_size, (void *)buffer);

    memcpy(buffer, data, data_len);
    buffer[data_len] = '\0';

    printf("[+] Stored OK (%zu bytes)\n", alloc_size);
    free(buffer);
    return 0;
}

int main(void) {
    printf("=== CWE-190: Integer Overflow — FIXED ===\n\n");

    /* Normal case */
    const char *normal = "Hello World";
    file_store_fixed(normal, strlen(normal));

    /* SIZE_MAX — correctly rejected */
    printf("\n[*] Attempting SIZE_MAX overflow...\n");
    file_store_fixed("X", (size_t)SIZE_MAX);

    /* Large but valid payload */
    printf("\n[*] Valid large payload:\n");
    char *big_data = calloc(1024, 1024);  /* 1 MB */
    if (big_data) {
        memset(big_data, 'X', 1024 * 1024);
        file_store_fixed(big_data, 1024 * 1024);
        free(big_data);
    }

    printf("\n[+] Integer overflow prevented.\n");
    printf("    Pattern:  if (a > MAX - b) overflow_error();\n");
    printf("    Also enforce an explicit MAX_PAYLOAD limit.\n");

    return 0;
}
