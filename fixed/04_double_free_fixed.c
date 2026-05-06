/*
 * FIXED: Double Free (CWE-415)
 *
 * Fixes applied:
 * 1. After free(p), immediately set p = NULL
 * 2. free(NULL) is a safe no-op per C standard
 * 3. Use macro SAFE_FREE(p) to enforce the pattern
 * 4. Eliminate goto-based cleanup — use single exit path
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SAFE_FREE(p) do { if ((p)) { free((p)); (p) = NULL; } } while (0)

typedef struct {
    int   fd;
    char *buffer;
    int   buf_size;
} connection_t;

/* FIXED: single free path, NULL after free */
static void conn_close_fixed(connection_t *conn, int error_path) {
    if (!conn) return;
    printf("[*] Closing connection fd=%d (error_path=%d)\n", conn->fd, error_path);

    if (error_path) {
        printf("[!] Error path: freeing buffer early (fd=%d)\n", conn->fd);
        SAFE_FREE(conn->buffer);  /* FIX: sets to NULL */
        /* no goto — fall through intentionally to demonstrate SAFE_FREE */
    }

    /* FIX: SAFE_FREE on NULL is a no-op — no double free! */
    printf("[*] Cleanup: SAFE_FREE(buffer)\n");
    SAFE_FREE(conn->buffer);  /* safe if already freed (is NULL) */

    if (conn->fd > 0) {
        close(conn->fd);
        conn->fd = -1;
    }

    SAFE_FREE(conn);
    printf("[+] Connection freed safely\n");
}

int main(void) {
    printf("=== CWE-415: Double Free — FIXED ===\n\n");

    /* Normal path */
    printf("--- Normal path ---\n");
    connection_t *conn1 = calloc(1, sizeof(connection_t));
    conn1->fd = 1;
    conn1->buffer = malloc(4096);
    conn1->buf_size = 4096;
    conn_close_fixed(conn1, 0);

    /* Error path — no double free! */
    printf("\n--- Error path (no double free!) ---\n");
    connection_t *conn2 = calloc(1, sizeof(connection_t));
    conn2->fd = 2;
    conn2->buffer = malloc(4096);
    conn2->buf_size = 4096;
    conn_close_fixed(conn2, 1);

    printf("\n[+] Double free prevented.\n");
    printf("    Key fix: always set pointer to NULL after free.\n");
    printf("    free(NULL) is guaranteed safe by the C standard.\n");

    return 0;
}
