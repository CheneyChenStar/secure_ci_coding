/*
 * FIXED: Format String Vulnerability (CWE-134)
 *
 * Fixes applied:
 * 1. Always use "%s" format specifier when logging user data
 * 2. Never pass user-controlled strings as the format argument
 * 3. Use compiler attributes to catch misuse at compile time
 */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

/* FIX: use __attribute__((format)) so compiler catches misuse */
__attribute__((format(printf, 2, 3)))
static void log_write_fixed(int level, const char *format, ...) {
    const char *levels[] = {"DEBUG", "INFO", "WARN", "ERROR"};

    printf("[%s] ", levels[level & 3]);

    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    printf("\n");
}

/* Wrapper that logs a plain string safely */
static void log_write_str(int level, const char *msg) {
    log_write_fixed(level, "%s", msg);
}

int main(int argc, char *argv[]) {
    printf("=== CWE-134: Format String — FIXED ===\n\n");

    const char *user_input = argc > 1 ? argv[1] : "%x.%x.%x.%x.%n";

    printf("[*] User input: '%s'\n", user_input);

    /* FIX 1: pass user data as variadic argument, not as format */
    printf("--- Fixed: user data as argument ---\n");
    log_write_fixed(1, "File uploaded: %s", user_input);

    /* FIX 2: dedicated string-logging function */
    printf("--- Fixed: dedicated string logger ---\n");
    log_write_str(1, user_input);

    printf("\n[*] Format specifiers in user input are printed literally, not interpreted.\n");
    printf("[*] Compiler attribute __format__ would warn if we passed user_input as format.\n");

    return 0;
}
