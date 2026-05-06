/*
 * VULNERABILITY: Double Free (CWE-415)
 *
 * Freeing the same heap pointer twice corrupts the allocator's internal
 * metadata (free list). This can lead to heap corruption and ultimately
 * arbitrary write primitives.
 *
 * PRINCIPLE: After free(p), always set p = NULL. free(NULL) is a safe
 * no-op per the C standard.
 *
 * IMPACT: Heap corruption, denial of service, or code execution via
 * heap exploitation techniques (e.g., tcache poisoning).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int   fd;
    char *buffer;
    int   buf_size;
} connection_t;

/* VULNERABLE: double free in error path */
static void conn_close_vuln(connection_t *conn, int error_path) {
    if (!conn) return;
    printf("[*] Closing connection fd=%d (error_path=%d)\n", conn->fd, error_path);

    if (error_path) {
        /* Simulate: shutdown fails, so we free early and jump to cleanup */
        printf("[!] Error path: freeing buffer early (fd=%d)\n", conn->fd);
        free(conn->buffer);
        /* BUG: conn->buffer is NOT set to NULL */
        goto cleanup;
    }

    /* Normal path */
    printf("[*] Normal path: freeing buffer\n");
    free(conn->buffer);

cleanup:
    /* BUG: on error_path, conn->buffer was already freed above.
     * This is the second free — DOUBLE FREE! */
    printf("[*] Cleanup: free(buffer) — ");
    if (conn->buffer) {
        printf("ptr=%p (DOUBLE FREE on error path!)\n", (void *)conn->buffer);
    } else {
        printf("ptr=NULL (safe)\n");
    }
    free(conn->buffer);  /* double free on error path */

    free(conn);
    printf("[*] Connection freed\n");
}

int main(void) {
    printf("=== CWE-415: Double Free Demo ===\n\n");

    /* Setup: create a connection */
    connection_t *conn = calloc(1, sizeof(connection_t));
    conn->fd = 42;
    conn->buffer = malloc(4096);
    conn->buf_size = 4096;
    strcpy(conn->buffer, "hello network data");
    printf("[+] Connection created, buffer at %p\n", (void *)conn->buffer);

    printf("\n--- Normal path (no double free) ---\n");
    connection_t *conn1 = calloc(1, sizeof(connection_t));
    conn1->fd = 1;
    conn1->buffer = malloc(4096);
    conn1->buf_size = 4096;
    conn_close_vuln(conn1, 0);

    printf("\n--- Error path (DOUBLE FREE!) ---\n");
    conn_close_vuln(conn, 1);

    printf("\n[!] The double free corrupts the heap. Subsequent malloc/free\n");
    printf("[!] may crash or produce exploitable conditions.\n");
    printf("[!] Use AddressSanitizer (-fsanitize=address) to detect this at runtime.\n");

    return 0;
}
