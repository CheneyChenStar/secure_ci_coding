/*
 * VULNERABILITY: Use-After-Free (CWE-416)
 *
 * A heap-allocated object is freed but the pointer is not set to NULL.
 * The dangling pointer is later dereferenced, reading/writing freed
 * memory that may have been reallocated to a different object.
 *
 * PRINCIPLE: After free(p), set p = NULL immediately. Check for NULL
 * before every dereference.
 *
 * IMPACT: Information leak, privilege escalation, or code execution
 * depending on what object replaces the freed memory.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    unsigned int session_id;
    int          user_id;
    time_t       expires_at;
    int          active;
} session_t;

static session_t *g_current_session = NULL;

static session_t *session_create(int user_id) {
    session_t *s = calloc(1, sizeof(session_t));
    s->session_id = 0xDEADBEEF;
    s->user_id = user_id;
    s->expires_at = time(NULL) + 3600;
    s->active = 1;
    printf("[+] Session created: id=%u user=%d\n", s->session_id, s->user_id);
    return s;
}

/* VULNERABLE: frees the session but does NOT set caller's pointer to NULL */
static void session_destroy(session_t *s) {
    printf("[*] Destroying session %p...\n", (void *)s);
    free(s);
    /* BUG: missing: s = NULL; — or equivalently, not communicating to caller */
}

static int session_is_valid(session_t *s) {
    /* BUG: dereferences 's' which may already be freed */
    return s && s->active && (time(NULL) < s->expires_at);
}

int main(void) {
    printf("=== CWE-416: Use-After-Free Demo ===\n\n");

    /* Step 1: create a session */
    g_current_session = session_create(42);

    /* Step 2: validate it (works fine) */
    printf("[*] Validating session... ");
    if (session_is_valid(g_current_session))
        printf("valid\n");
    else
        printf("invalid\n");

    /* Step 3: destroy the session — but g_current_session still points to it! */
    session_destroy(g_current_session);
    /* At this point, g_current_session is a dangling pointer.
     * The heap memory may still contain old data, or it may be reused. */

    /* Step 4: allocate some other data to reuse the freed memory */
    printf("[*] Allocating new objects (may reuse freed session memory)...\n");
    char *decoy1 = malloc(sizeof(session_t));
    memset(decoy1, 0xFF, sizeof(session_t));  /* overwrite with garbage */
    char *decoy2 = malloc(sizeof(session_t));
    memset(decoy2, 'B', sizeof(session_t));   /* overwrite with 'B's */
    free(decoy1);
    free(decoy2);

    /* Step 5: USE AFTER FREE — validates against freed (now corrupted) memory */
    printf("[*] Validating session AFTER free... ");
    if (session_is_valid(g_current_session)) {
        /* We might read garbage and think the session is still valid! */
        printf("valid (BUG! Use-After-Free may report stale data as valid)\n");
    } else {
        printf("invalid (expected, but only because memory happened to be corrupted)\n");
    }

    printf("\n[!] This is undefined behavior. Actual results vary by platform.\n");
    printf("[!] With AddressSanitizer: ./vuln_uaf will crash cleanly.\n");

    return 0;
}
