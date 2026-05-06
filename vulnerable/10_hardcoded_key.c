/*
 * VULNERABILITY: Hardcoded Credentials / Key (CWE-798)
 *
 * Embedding cryptographic keys or credentials directly in source code
 * makes them visible in:
 * - Binary (extractable via `strings` command)
 * - Version control history (git log)
 * - Debug symbols
 * - Decompilation output
 *
 * PRINCIPLE: Never hardcode secrets. Use environment variables, secure
 * key stores (KMS, Vault), or configuration files with restricted
 * permissions. Use standard password hashing algorithms (bcrypt, scrypt,
 * argon2) instead of custom encryption.
 *
 * IMPACT: Anyone with binary access extracts the key, compromising all
 * data encrypted with it and all user credentials.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ═══════════════════════════════════════════════════════════════════
 * VULNERABLE: Hardcoded encryption key in binary
 *
 * Extract with:  strings ./vuln_hardcoded | grep Secret
 * ═══════════════════════════════════════════════════════════════════ */

#define HARDCODED_KEY "SecretKey2024!@#"  /* visible in binary! */
#define HARDCODED_IV  "InitVector12345"   /* also visible */

static void encrypt_password_vuln(const char *password, char *out) {
    size_t key_len = strlen(HARDCODED_KEY);
    size_t pw_len = strlen(password);

    printf("[*] Using hardcoded key: '%s'\n", HARDCODED_KEY);

    /* Trivial XOR "encryption" — already weak, made worse by hardcoded key */
    char temp[64] = {0};
    for (size_t i = 0; i < pw_len && i < 63; i++) {
        temp[i] = password[i] ^ HARDCODED_KEY[i % key_len];
    }

    /* Hex-encode the result */
    for (size_t i = 0; i < 32; i++) {
        snprintf(out + i * 2, 3, "%02x", (unsigned char)temp[i]);
    }
    out[64] = '\0';
}

/* ═══════════════════════════════════════════════════════════════════
 * FIXED: Key from environment variable, uses PBKDF2
 * ═══════════════════════════════════════════════════════════════════ */

#include <openssl/evp.h>

static void hash_password_fixed(const char *password, char *out) {
    /* Read key from environment (never in code!) */
    const char *env_key = getenv("SECUREFILE_ENC_KEY");
    if (!env_key) {
        printf("[-] SECUREFILE_ENC_KEY not set! Using fallback.\n");
        env_key = "fallback-not-for-production!";
    }

    printf("[*] Key from environment (first 4 chars): %.4s***\n", env_key);

    /* Generate random salt */
    unsigned char salt[16];
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom) {
        fread(salt, 1, sizeof(salt), urandom);
        fclose(urandom);
    } else {
        for (int i = 0; i < 16; i++) salt[i] = (unsigned char)(rand() & 0xFF);
    }

    /* Derive key using PBKDF2 (10,000 iterations) */
    unsigned char derived[32];
    PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                      salt, sizeof(salt),
                      10000, EVP_sha256(),
                      sizeof(derived), derived);

    /* Encode salt + derived as hex */
    for (int i = 0; i < 16; i++)
        snprintf(out + i * 2, 3, "%02x", salt[i]);
    for (int i = 0; i < 32; i++)
        snprintf(out + 32 + i * 2, 3, "%02x", derived[i]);
    out[96] = '\0';
}

int main(void) {
    printf("=== CWE-798: Hardcoded Key Demo ===\n\n");

    const char *password = "MySecretPassword123";

    /* Vulnerable: hardcoded key */
    printf("--- Vulnerable (hardcoded key) ---\n");
    char vuln_hash[65];
    encrypt_password_vuln(password, vuln_hash);
    printf("[+] Hash: %s\n", vuln_hash);
    printf("[!] Key extractable via: strings %s | grep Secret\n\n", __FILE__);

    /* Fixed: env var + PBKDF2 */
    printf("--- Fixed (env var + PBKDF2) ---\n");
    char fixed_hash[97];
    hash_password_fixed(password, fixed_hash);
    printf("[+] Hash: %s\n", fixed_hash);

    printf("\n[!] Key takeaways:\n");
    printf("    1. Never embed keys in source code\n");
    printf("    2. Use environment variables or key management services\n");
    printf("    3. Use standard password hashing: bcrypt, scrypt, argon2\n");
    printf("    4. Always add salt, use high iteration counts\n");

    return 0;
}
