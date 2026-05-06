#include "session.h"
#include "logger.h"

session_t *g_sessions[MAX_CONNECTIONS] = {0};
int        g_session_count = 0;
pthread_mutex_t g_session_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ───────────────────────────────────────────────────────────────────
 * VULNERABILITY: Insecure Random Number Generation
 *
 * session_create() uses rand() to generate session IDs and tokens.
 * rand() is a deterministic LCG — without a proper seed it produces
 * the same sequence every time.  Even with srand(time(NULL)), seeds
 * are predictable to within seconds, allowing an attacker to guess
 * valid session IDs and hijack user sessions.
 *
 * Additionally, rand() has only 2^31 possible states, so brute-force
 * enumeration of session IDs is feasible.
 * ─────────────────────────────────────────────────────────────────── */

static uint32_t generate_session_id(void) {
#ifdef FIXED
    /* FIXED: use /dev/urandom for cryptographically secure IDs */
    uint32_t id;
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom) {
        if (fread(&id, sizeof(id), 1, urandom) != 1) {
            /* fallback if read fails */
            id = (uint32_t)time(NULL) ^ (uint32_t)getpid();
        }
        fclose(urandom);
    } else {
        id = (uint32_t)time(NULL) ^ (uint32_t)getpid();
    }
    return id;
#else
    /* VULNERABLE: predictable rand() — no srand() call, default seed 1 */
    return (uint32_t)rand();
#endif
}

static void generate_token(char *token_out, size_t len) {
#ifdef FIXED
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom) {
        unsigned char buf[SESSION_TOKEN_LEN];
        size_t n = fread(buf, 1, len - 1, urandom);
        fclose(urandom);
        for (size_t i = 0; i < n; i++) {
            snprintf(token_out + i * 2, 3, "%02x", buf[i]);
        }
    } else {
        /* fallback — not ideal */
        for (size_t i = 0; i < len - 1; i += 2) {
            snprintf(token_out + i, 3, "%02x", (unsigned int)(rand() & 0xFF));
        }
    }
#else
    /* VULNERABLE: rand() for session tokens — predictable */
    for (size_t i = 0; i < len - 1; i += 8) {
        snprintf(token_out + i, 9, "%08x", (unsigned int)rand());
    }
#endif
    token_out[len - 1] = '\0';
}

uint32_t session_create(int user_id, user_role_t role, char *token_out) {
    uint32_t sid = generate_session_id();
    generate_token(token_out, SESSION_TOKEN_LEN);

    session_t *s = calloc(1, sizeof(session_t));
    if (!s) return 0;

    s->session_id = sid;
    s->user_id = user_id;
    s->role = role;
    memcpy(s->token, token_out, SESSION_TOKEN_LEN);
    s->created_at = time(NULL);
    s->expires_at = s->created_at + SESSION_TIMEOUT_SEC;
    s->active = 1;

    pthread_mutex_lock(&g_session_mutex);
    if (g_session_count < MAX_CONNECTIONS) {
        g_sessions[g_session_count++] = s;
    } else {
        pthread_mutex_unlock(&g_session_mutex);
        free(s);
        LOG_ERROR("Session table full");
        return 0;
    }
    pthread_mutex_unlock(&g_session_mutex);

    LOG_DEBUG("Session created: id=%u user=%d", sid, user_id);
    return sid;
}

session_t *session_lookup(uint32_t session_id) {
    pthread_mutex_lock(&g_session_mutex);
    for (int i = 0; i < g_session_count; i++) {
        if (g_sessions[i] && g_sessions[i]->session_id == session_id
            && g_sessions[i]->active) {
            pthread_mutex_unlock(&g_session_mutex);
            return g_sessions[i];
        }
    }
    pthread_mutex_unlock(&g_session_mutex);
    return NULL;
}

/* ───────────────────────────────────────────────────────────────────
 * VULNERABILITY: Use-After-Free
 *
 * session_destroy_by_ptr() frees the session_t object but does NOT
 * set the caller's pointer to NULL.  The caller's pointer becomes a
 * dangling pointer.  If session_validate() is subsequently called on
 * that pointer, it reads freed heap memory (use-after-free).
 *
 * An attacker who can control heap allocation between the free and
 * the use can place controlled data where s->active and s->expires_at
 * used to be, potentially bypassing session validation.
 * ─────────────────────────────────────────────────────────────────── */
void session_destroy_by_ptr(session_t *s) {
    if (!s) return;

    pthread_mutex_lock(&g_session_mutex);
    s->active = 0;
    for (int i = 0; i < g_session_count; i++) {
        if (g_sessions[i] == s) {
            free(g_sessions[i]);
#ifdef FIXED
            g_sessions[i] = NULL;  /* FIXED: prevent UAF via table */
#endif
            /* Compact the array */
            for (int j = i; j < g_session_count - 1; j++) {
                g_sessions[j] = g_sessions[j + 1];
            }
            g_sessions[--g_session_count] = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&g_session_mutex);

    /* NOTE: The caller's pointer (e.g., conn->session) is NOT set to NULL.
     * This is the root cause of the UAF — the caller holds a dangling ref. */
    LOG_DEBUG("Session destroyed: id=%u", s->session_id);
}

void session_destroy(uint32_t session_id) {
    session_t *s = session_lookup(session_id);
    if (s) {
        session_destroy_by_ptr(s);
    }
}

int session_validate(session_t *s) {
    if (!s) return 0;

#ifdef FIXED
    /* FIXED: additional integrity check */
    pthread_mutex_lock(&g_session_mutex);
    int found = 0;
    for (int i = 0; i < g_session_count; i++) {
        if (g_sessions[i] == s) {
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_session_mutex);
    if (!found) return 0;  /* s is not in the table — already freed */
#endif

    /* VULNERABLE: accesses s->active on potentially freed memory */
    return s->active && (time(NULL) <= s->expires_at);
}

void session_cleanup_expired(void) {
    time_t now = time(NULL);
    pthread_mutex_lock(&g_session_mutex);
    for (int i = g_session_count - 1; i >= 0; i--) {
        if (g_sessions[i] && (g_sessions[i]->expires_at <= now || !g_sessions[i]->active)) {
            free(g_sessions[i]);
            for (int j = i; j < g_session_count - 1; j++) {
                g_sessions[j] = g_sessions[j + 1];
            }
            g_sessions[--g_session_count] = NULL;
        }
    }
    pthread_mutex_unlock(&g_session_mutex);
}
