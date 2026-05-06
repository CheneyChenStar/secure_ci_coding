#include "auth.h"
#include "logger.h"

#ifdef FIXED
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

user_t g_user_db[USER_DB_MAX];
int    g_user_count = 0;

/* ───────────────────────────────────────────────────────────────────
 * VULNERABILITY: Hardcoded Key
 *
 * A static AES encryption key is embedded in the binary.  Anyone
 * with access to the binary can extract it with:
 *     strings securefile_server | grep SecretKey
 *
 * This key is used to "protect" password hashes, but since it is
 * known to all attackers, the protection is worthless.
 * ─────────────────────────────────────────────────────────────────── */

void auth_hash_password(const char *password, char *hash_out) {
#ifdef FIXED
    /* FIXED: use bcrypt-like approach via OpenSSL PBKDF2 */
    unsigned char salt[16];
    unsigned char derived[32];

    /* Read salt from /dev/urandom */
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom) {
        fread(salt, 1, sizeof(salt), urandom);
        fclose(urandom);
    } else {
        /* Fallback — not ideal but OK for training */
        for (size_t i = 0; i < sizeof(salt); i++) salt[i] = (unsigned char)(rand() & 0xFF);
    }

    PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                      salt, sizeof(salt), 10000,
                      EVP_sha256(), sizeof(derived), derived);

    /* Encode salt + derived key as hex */
    for (size_t i = 0; i < sizeof(salt); i++)
        snprintf(hash_out + i * 2, 3, "%02x", salt[i]);
    for (size_t i = 0; i < sizeof(derived); i++)
        snprintf(hash_out + sizeof(salt) * 2 + i * 2, 3, "%02x", derived[i]);
    hash_out[32 + 64] = '\0';

#else
    /* VULNERABLE: hardcoded key, custom "encryption" (trivial XOR) */
    const char key[] = "SecretKey2024!@#";
    size_t key_len = strlen(key);
    size_t pw_len = strlen(password);
    char hash_buf[64] = {0};

    for (size_t i = 0; i < pw_len && i < 63; i++) {
        hash_buf[i] = password[i] ^ key[i % key_len];
    }

    /* Encode as hex for readability */
    for (size_t i = 0; i < 32; i++) {
        snprintf(hash_out + i * 2, 3, "%02x", (unsigned char)hash_buf[i]);
    }
    hash_out[64] = '\0';
#endif
}

/* ───────────────────────────────────────────────────────────────────
 * VULNERABILITY: Unchecked Input
 *
 * auth_verify() does not validate the length or content of username
 * before using it in string operations.  An extremely long username
 * (e.g., > MAX_USERNAME_LEN) can overflow internal buffers when
 * copied or logged.  Also, no character allow-list is enforced.
 * ─────────────────────────────────────────────────────────────────── */
int auth_verify(const char *username, const char *password) {
    if (!username || !password) return 0;

#ifdef FIXED
    /* FIXED: validate input before processing */
    size_t uname_len = strlen(username);
    size_t pw_len = strlen(password);

    if (uname_len == 0 || uname_len >= MAX_USERNAME_LEN) {
        LOG_WARN("Username length %zu out of range", uname_len);
        return 0;
    }
    if (pw_len == 0 || pw_len >= MAX_PASSWORD_LEN) {
        LOG_WARN("Password length out of range");
        return 0;
    }

    /* Validate character set — alphanumeric and underscore only */
    for (size_t i = 0; i < uname_len; i++) {
        char c = username[i];
        if (!((c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
              c == '_' || c == '-' || c == '.')) {
            LOG_WARN("Illegal character in username: 0x%02x", (unsigned char)c);
            return 0;
        }
    }
#endif

    /* Look up user */
    char compare_hash[64];
    auth_hash_password(password, compare_hash);

    for (int i = 0; i < g_user_count; i++) {
        if (!g_user_db[i].active) continue;
        if (strcmp(g_user_db[i].username, username) == 0) {
            if (strcmp(g_user_db[i].password_hash, compare_hash) == 0) {
                LOG_INFO("User '%s' authenticated successfully", username);
                return 1;
            }
            LOG_WARN("Authentication failed for user '%s': wrong password", username);
            return 0;
        }
    }

    LOG_WARN("Authentication failed: unknown user '%s'", username);
    return 0;
}

user_t *auth_lookup_user(const char *username) {
    for (int i = 0; i < g_user_count; i++) {
        if (!g_user_db[i].active) continue;
        if (strcmp(g_user_db[i].username, username) == 0) {
            return &g_user_db[i];
        }
    }
    return NULL;
}

int auth_user_exists(const char *username) {
    return auth_lookup_user(username) != NULL;
}

int auth_create_user(const char *username, const char *password, user_role_t role) {
    if (g_user_count >= USER_DB_MAX) return -1;
    if (strlen(username) >= MAX_USERNAME_LEN) return -1;

    user_t *u = &g_user_db[g_user_count];
    u->user_id = g_user_count + 1;
    strncpy(u->username, username, MAX_USERNAME_LEN - 1);
    u->username[MAX_USERNAME_LEN - 1] = '\0';
    auth_hash_password(password, u->password_hash);
    u->role = role;
    u->active = 1;
    g_user_count++;

    LOG_INFO("User created: %s (id=%d, role=%d)", username, u->user_id, role);
    return 0;
}

int auth_init(const char *user_db_path) {
    UNUSED(user_db_path);

    /* Seed with default users for training */
    auth_create_user("admin", "Admin@SecureFile2024!", ROLE_ADMIN);
    auth_create_user("alice", "AliceSecret123", ROLE_USER);
    auth_create_user("bob", "BobPassword456", ROLE_USER);

    LOG_INFO("Auth module initialized with %d users", g_user_count);
    return 0;
}
