/*
 * Test Runner — executes all test suites and reports results.
 *
 * In a real project, use a framework like CUnit, Check, or Criterion.
 * For this training project, we simply chain the individual test binaries.
 */

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    printf("========================================\n");
    printf(" SecureFile Vault — Test Suite Runner\n");
    printf("========================================\n\n");

    int total = 0;
    int failed = 0;

    const char *tests[] = {
        "test_auth",
        "test_protocol",
        "test_file_handler",
        "test_security",
        NULL
    };

    for (int i = 0; tests[i] != NULL; i++) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "./build/%s", tests[i]);
        printf("--- Running: %s ---\n", tests[i]);
        int ret = system(cmd);
        if (ret != 0) {
            failed++;
        }
        total++;
        printf("\n");
    }

    printf("========================================\n");
    printf(" Test Results: %d/%d suites passed\n", total - failed, total);
    printf("========================================\n");

    return failed > 0 ? 1 : 0;
}
