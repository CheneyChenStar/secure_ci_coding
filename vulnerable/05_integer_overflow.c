/*
 * VULNERABILITY: Integer Overflow (CWE-190)
 *
 * When arithmetic operations on unsigned integers wrap around
 * (e.g., SIZE_MAX + 1 = 0), the resulting value can cause
 * insufficient memory allocation followed by a buffer overflow.
 *
 * PRINCIPLE: Always check that arithmetic results don't wrap.
 * For size_t: check data_len < SIZE_MAX before data_len + 1.
 *
 * IMPACT: Heap buffer overflow → arbitrary code execution.
 * Real-world: CVE-2012-2127 in Linux kernel.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

/* Vulnerable file store */
static int file_store_vuln(const char *data, size_t data_len) {
    printf("[*] file_store(data_len=%zu)\n", data_len);

    /* BUG: data_len + 1 can overflow to 0 when data_len == SIZE_MAX
     * malloc(0) is implementation-defined — may return NULL or a small buffer */
    size_t alloc_size = data_len + 1;
    char *buffer = malloc(alloc_size);

    if (!buffer) {
        printf("[-] malloc(%zu) returned NULL\n", alloc_size);
        return -1;
    }

    printf("[*] Allocated %zu bytes at %p (requested %zu)\n",
           alloc_size, (void *)buffer, data_len + 1);

    /* BUG: memcpy of SIZE_MAX bytes into a potentially tiny buffer */
    memcpy(buffer, data, data_len);
    buffer[data_len] = '\0';  /* also overflows */

    printf("[+] Stored OK\n");
    free(buffer);
    return 0;
}

/* Fixed version */
static int file_store_fixed(const char *data, size_t data_len) {
    printf("\n[*] file_store_fixed(data_len=%zu)\n", data_len);

    /* FIX: check for overflow before arithmetic */
    if (data_len >= SIZE_MAX - 1) {
        printf("[-] Integer overflow prevented: data_len=%zu\n", data_len);
        return -1;
    }

    size_t alloc_size = data_len + 1;  /* safe: no overflow possible */
    char *buffer = malloc(alloc_size);

    if (!buffer) {
        printf("[-] malloc(%zu) returned NULL\n", alloc_size);
        return -1;
    }

    memcpy(buffer, data, data_len);
    buffer[data_len] = '\0';

    printf("[+] Stored OK (%zu bytes)\n", alloc_size);
    free(buffer);
    return 0;
}

int main(void) {
    printf("=== CWE-190: Integer Overflow Demo ===\n\n");

    /* Normal case */
    const char *normal_data = "Hello World";
    file_store_vuln(normal_data, strlen(normal_data));

    /* Overflow case: SIZE_MAX */
    printf("\n[*] Attempting SIZE_MAX overflow...\n");

    /* We can't actually allocate SIZE_MAX bytes, so we demonstrate
     * the principle with a large (but safe) test that triggers the
     * vulnerability logic */
    size_t huge = (size_t)SIZE_MAX;
    file_store_vuln("X", huge);  /* malloc(0) — undefined behavior */

    /* Fixed version prevents this */
    file_store_fixed("X", huge);

    printf("\n[!] Key takeaway: always validate integer operations.\n");
    printf("[!] Rule:  if (a > SIZE_MAX - b) overflow!\n");

    return 0;
}
