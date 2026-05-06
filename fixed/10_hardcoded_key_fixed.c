/*
 * FIXED: Hardcoded Key / Credentials (CWE-798)
 *
 * Fixes applied:
 * 1. Read encryption key from environment variable (never in source)
 * 2. Use PBKDF2 with random salt for password hashing
 * 3. Use industry-standard algorithms, not custom crypto
 * 4. Store only the salt + derived key, never the raw key
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/*
 * FIX: key is read from environment at runtime, not compiled in.
 *
 * In production, use a key management service (AWS KMS, HashiCorp Vault).
 * For this training project, the env var approach is sufficient.
 */
static int load_key_from_env(unsigned char *key, size_t key_len) {
    const char *env_key = getenv("SECUREFILE_ENC_KEY");
    if (!env_key) {
        printf("[-] SECUREFILE_ENC_KEY not set!\n");
        printf("    Set it with: export SECUREFILE_ENC_KEY=\"your-secret-key\"\n");
        return -1;
    }

    /* Derive a fixed-length key from the env value using SHA-256 */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, env_key, strlen(env_key));

    unsigned int out_len = 0;
    EVP_DigestFinal_ex(ctx, key, &out_len);
    EVP_MD_CTX_free(ctx);

    if (out_len > (unsigned int)key_len) out_len = (unsigned int)key_len;
    printf("[*] Key derived from SECUREFILE_ENC_KEY (len=%u)\n", out_len);
    return 0;
}

/* FIX: PBKDF2 with random salt for password hashing */
static int hash_password_fixed(const char *password, char *out, size_t out_len) {
    unsigned char key[32];
    unsigned char salt[16];

    /* Load encryption key from environment */
    if (load_key_from_env(key, sizeof(key)) != 0) {
        /* Fallback: generate a random key for this session (not for production!) */
        printf("[!] Using session-random fallback key (not for production!)\n");
        RAND_bytes(key, sizeof(key));
    }

    /* Generate cryptographically random salt */
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        /* Fallback */
        FILE *urandom = fopen("/dev/urandom", "rb");
        if (urandom) {
            fread(salt, 1, sizeof(salt), urandom);
            fclose(urandom);
        }
    }

    /* Derive password hash using PBKDF2-HMAC-SHA256
     * 100,000 iterations as per OWASP recommendation (2023+) */
    unsigned char derived[32];
    PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                      salt, sizeof(salt),
                      100000,
                      EVP_sha256(),
                      sizeof(derived), derived);

    /* Encode salt + derived key as hex
     * Format: salt(32 hex chars) + hash(64 hex chars) = 96 chars */
    if (out_len < 97) return -1;

    for (int i = 0; i < 16; i++)
        snprintf(out + i * 2, 3, "%02x", salt[i]);
    for (int i = 0; i < 32; i++)
        snprintf(out + 32 + i * 2, 3, "%02x", derived[i]);
    out[96] = '\0';

    return 0;
}

int main(void) {
    printf("=== CWE-798: Hardcoded Key — FIXED ===\n\n");

    const char *password = "MySecretPassword123";

    printf("--- Fixed (env var + PBKDF2) ---\n");
    char fixed_hash[128];
    if (hash_password_fixed(password, fixed_hash, sizeof(fixed_hash)) == 0) {
        printf("[+] Hash: %s\n", fixed_hash);
        printf("[+] Salt: %s (first 32 hex chars)\n", fixed_hash);
    } else {
        printf("[-] Hashing failed (SECUREFILE_ENC_KEY not set?)\n");
        printf("    Try: export SECUREFILE_ENC_KEY=\"my-training-key-$(date +%%s)\"\n");
    }

    printf("\n[+] Hardcoded key eliminated.\n");
    printf("    Key management best practices:\n");
    printf("    1. NEVER put keys in source code\n");
    printf("    2. Use environment variables for dev/test\n");
    printf("    3. Use KMS (AWS KMS, Vault) for production\n");
    printf("    4. Rotate keys regularly\n");
    printf("    5. Use standard algorithms: bcrypt, scrypt, argon2, PBKDF2\n");
    printf("    6. Always add random salt, use 100K+ iterations\n");

    return 0;
}
