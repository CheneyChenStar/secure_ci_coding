/*
 * FIXED: Use-After-Free (CWE-416)
 *
 * Fixes applied:
 * 1. After free(s), set the pointer variable to NULL (or return it via double pointer)
 * 2. Check for NULL before every dereference
 * 3. Use a validity check that verifies the object is still in the live table
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

static session_t *g_session_table[16];
static int        g_session_count = 0;

static session_t *session_create(int user_id) {
    session_t *s = calloc(1, sizeof(session_t));
    s->session_id = 0xDEADBEEF;
    s->user_id = user_id;
    s->expires_at = time(NULL) + 3600;
    s->active = 1;

    if (g_session_count < 16) {
        g_session_table[g_session_count++] = s;
    }
    printf("[+] Session created: id=%u user=%d\n", s->session_id, s->user_id);
    return s;
}

/* FIX: takes a double pointer so we can NULL the caller's pointer */
static void session_destroy(session_t **s_ptr) {
    if (!s_ptr || !*s_ptr) return;

    session_t *s = *s_ptr;
    printf("[*] Destroying session %p...\n", (void *)s);

    /* Remove from table */
    for (int i = 0; i < g_session_count; i++) {
        if (g_session_table[i] == s) {
            free(s);
            g_session_table[i] = NULL;
            /* Compact */
            for (int j = i; j < g_session_count - 1; j++) {
                g_session_table[j] = g_session_table[j + 1];
            }
            g_session_table[--g_session_count] = NULL;
            break;
        }
    }

    /* FIX: NULL the caller's pointer to prevent UAF */
    *s_ptr = NULL;
    printf("[+] Caller's pointer set to NULL\n");
}

/* FIX: validate by checking the object is in the live table */
static int session_is_valid(session_t *s) {
    if (!s) return 0;  /* FIX: NULL check — free(NULL) is safe */

    /* FIX: additional integrity check — verify object is still in table */
    for (int i = 0; i < g_session_count; i++) {
        if (g_session_table[i] == s) {
            return s->active && (time(NULL) < s->expires_at);
        }
    }
    return 0;
}

int main(void) {
    printf("=== CWE-416: Use-After-Free — FIXED ===\n\n");

    session_t *s = session_create(42);

    printf("[*] Validating: %s\n", session_is_valid(s) ? "valid" : "invalid");

    /* FIX: pass address of pointer so it can be NULLed */
    session_destroy(&s);

    /* FIX: s is now NULL, so dereference is safe */
    printf("[*] After destroy, pointer = %p\n", (void *)s);
    printf("[*] Validating: %s (no UAF!)\n", session_is_valid(s) ? "valid" : "invalid");

    printf("\n[+] Use-After-Free successfully prevented.\n");
    printf("    Key fix: free() + set pointer to NULL + NULL check before use.\n");

    return 0;
}
