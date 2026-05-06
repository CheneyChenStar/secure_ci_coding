/*
 * VULNERABILITY: Format String (CWE-134)
 *
 * When user-controlled data is passed directly as the format argument
 * to a printf-family function, the attacker controls the format string
 * and can read (%x, %p) or write (%n) arbitrary memory.
 *
 * PRINCIPLE: printf(user_input) treats user_input as a format string.
 * Use printf("%s", user_input) instead.
 *
 * IMPACT: Information disclosure (stack/memory leak), arbitrary write.
 */

#include <stdio.h>
#include <string.h>

/* Simulated log_write — the VULNERABLE variant */
static void log_write_vuln(int level, const char *format, ...) {
    const char *levels[] = {"DEBUG", "INFO", "WARN", "ERROR"};

    printf("[%s] ", levels[level & 3]);

    /* VULNERABLE: user-controlled 'format' passed to vprintf directly */
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    printf("\n");
}

/* FIXED variant (shown for comparison) */
static void log_write_fixed(int level, const char *msg) {
    const char *levels[] = {"DEBUG", "INFO", "WARN", "ERROR"};
    printf("[%s] %s\n", levels[level & 3], msg);
}

int main(int argc, char *argv[]) {
    printf("=== CWE-134: Format String Vulnerability Demo ===\n\n");

    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        printf("\nTry these attack payloads:\n");
        printf("  %s \"test.txt\"\n", argv[0]);
        printf("  %s \"%%x.%%x.%%x.%%x\"         (stack leak)\n", argv[0]);
        printf("  %s \"%%s\"                       (dereference pointer)\n", argv[0]);
        printf("  %s \"AAAA%%x%%x%%x%%x%%x%%x%%n\" (arbitrary write)\n", argv[0]);
        return 0;
    }

    /* Simulate: file upload handler logs the filename */
    printf("[*] Vulnerable log (user input as format string):\n");
    log_write_vuln(1, argv[1]);

    printf("\n[*] Fixed log (user input as argument):\n");
    log_write_fixed(1, argv[1]);

    return 0;
}
