/*
 * VULNERABILITY: Insecure Random Number Generation (CWE-338)
 *
 * rand() is a deterministic PRNG (Linear Congruential Generator).
 * Without a proper seed, it produces the same sequence every run.
 * Even with srand(time(NULL)), the seed is predictable within seconds,
 * making session IDs and tokens guessable.
 *
 * PRINCIPLE: Use cryptographically secure random sources for security
 * tokens: /dev/urandom, getrandom(), or arc4random() on BSD/macOS.
 *
 * IMPACT: Session hijacking, CSRF token bypass, predictable password
 * reset tokens.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* VULNERABLE: uses rand() for session token generation */
static void generate_token_vuln(char *buf, size_t len) {
    /* No srand() call — default seed is 1, same sequence every time! */
    for (size_t i = 0; i < len - 1; i += 8) {
        snprintf(buf + i, 9, "%08x", (unsigned int)rand());
    }
    buf[len - 1] = '\0';
}

/* FIXED: reads from /dev/urandom */
static void generate_token_fixed(char *buf, size_t len) {
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom) {
        unsigned char raw[64];
        size_t n = fread(raw, 1, (len - 1) / 2, urandom);
        fclose(urandom);
        for (size_t i = 0; i < n; i++) {
            snprintf(buf + i * 2, 3, "%02x", raw[i]);
        }
    } else {
        /* Fallback — not ideal */
        for (size_t i = 0; i < len - 1; i += 2) {
            snprintf(buf + i, 3, "%02x", (unsigned int)(rand() & 0xFF));
        }
    }
    buf[len - 1] = '\0';
}

int main(void) {
    printf("=== CWE-338: Insecure Random Number Demo ===\n\n");

    char token_vuln[65];
    char token_fixed[65];

    /* Vulnerable generation — repeated runs produce same output! */
    printf("[*] Vulnerable tokens (rand() with default seed=1):\n");
    printf("    Run 1: ");
    generate_token_vuln(token_vuln, 65);
    printf("%s\n", token_vuln);

    printf("    Run 2: ");
    generate_token_vuln(token_vuln, 65);
    printf("%s\n", token_vuln);
    printf("    (Same values? rand() sequence is deterministic)\n");

    /* Even with time-based seed, the token is predictable */
    srand((unsigned int)time(NULL));
    printf("\n[*] Vulnerable token (srand(time)): ");
    generate_token_vuln(token_vuln, 65);
    printf("%s\n", token_vuln);
    printf("    (An attacker who knows approximate server time can guess this)\n");

    /* Fixed version */
    printf("\n[*] Fixed token (/dev/urandom):\n");
    printf("    Run 1: ");
    generate_token_fixed(token_fixed, 65);
    printf("%s\n", token_fixed);
    printf("    Run 2: ");
    generate_token_fixed(token_fixed, 65);
    printf("%s\n", token_fixed);

    printf("\n[!] Key takeaway: NEVER use rand() for security tokens.\n");
    printf("[!] Use /dev/urandom or getrandom() instead.\n");

    return 0;
}
