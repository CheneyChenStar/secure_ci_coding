/*
 * Unit Tests: Authentication Module
 *
 * Tests:
 * 1. Creating users with valid credentials
 * 2. Login with correct password → success
 * 3. Login with wrong password → failure
 * 4. Non-existent user → failure
 * 5. Input validation edge cases
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "../include/common.h"
#include "../include/auth.h"

static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST(name) do { \
    printf("  TEST: %-50s ", name); \
} while (0)

#define CHECK(cond) do { \
    if (cond) { \
        printf("PASS\n"); \
        g_tests_passed++; \
    } else { \
        printf("FAIL  [%s:%d]\n", __FILE__, __LINE__); \
        g_tests_failed++; \
    } \
} while (0)

int main(void) {
    printf("=== Test: Authentication Module ===\n\n");

    /* Initialize */
    auth_init(NULL);
    printf("[*] Users in DB: %d\n\n", g_user_count);

    /* Test 1: Known user, correct password */
    TEST("Known user with correct password should authenticate");
    CHECK(auth_verify("admin", "Admin@SecureFile2024!") == 1);

    /* Test 2: Known user, wrong password */
    TEST("Known user with wrong password should fail");
    CHECK(auth_verify("admin", "wrongpassword") == 0);

    /* Test 3: Non-existent user */
    TEST("Non-existent user should fail");
    CHECK(auth_verify("nonexistent", "anything") == 0);

    /* Test 4: Create new user and verify */
    TEST("Create user and authenticate");
    auth_create_user("charlie", "CharliePwd789", ROLE_USER);
    CHECK(auth_verify("charlie", "CharliePwd789") == 1);

    /* Test 5: NULL inputs */
    TEST("NULL username should fail gracefully");
    CHECK(auth_verify(NULL, "test") == 0);

    TEST("NULL password should fail gracefully");
    CHECK(auth_verify("admin", NULL) == 0);

    /* Test 6: Empty strings */
    TEST("Empty username should fail");
    CHECK(auth_verify("", "test") == 0);

    /* Test 7: User lookup */
    TEST("Lookup existing user");
    user_t *u = auth_lookup_user("alice");
    CHECK(u != NULL && strcmp(u->username, "alice") == 0);

    TEST("Lookup non-existent user");
    CHECK(auth_lookup_user("nobody") == NULL);

    /* Test 8: Password hash is not plaintext */
    TEST("Password hash should differ from plaintext");
    char hash[64];
    auth_hash_password("testpassword", hash);
    CHECK(strcmp(hash, "testpassword") != 0);

    /* Summary */
    printf("\n=== Authentication Tests: %d passed, %d failed ===\n",
           g_tests_passed, g_tests_failed);

    return g_tests_failed > 0 ? 1 : 0;
}
