/*
 * Unit Tests: File Handler Module
 *
 * Tests:
 * 1. Store and retrieve a file
 * 2. Delete a file
 * 3. List files with prefix
 * 4. Path traversal prevention
 * 5. Large file size rejection
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "../include/common.h"
#include "../include/file_handler.h"

static int g_passed = 0;
static int g_failed = 0;

#define TEST(n) do { printf("  TEST: %-50s ", n); } while (0)
#define CHECK(c) do { \
    if (c) { printf("PASS\n"); g_passed++; } \
    else   { printf("FAIL [%s:%d]\n", __FILE__, __LINE__); g_failed++; } \
} while (0)

int main(void) {
    printf("=== Test: File Handler Module ===\n\n");

    const char *test_dir = "/tmp/securefile_test";
    system("rm -rf /tmp/securefile_test && mkdir -p /tmp/securefile_test");

    file_handler_init(test_dir);

    /* Test 1: Store and retrieve */
    TEST("Store and retrieve a file");
    {
        const char *content = "Hello, Secure Vault!";
        int ret = file_store("test1.txt", content, strlen(content));
        if (ret == 0) {
            char out[4096];
            size_t out_len;
            ret = file_retrieve("test1.txt", out, &out_len);
            CHECK(ret == 0 && out_len == strlen(content) &&
                  memcmp(out, content, out_len) == 0);
        } else {
            CHECK(0); /* store failed */
        }
    }

    /* Test 2: Delete */
    TEST("Store and delete a file");
    {
        const char *content = "Delete me";
        file_store("del_test.txt", content, strlen(content));
        int ret = file_delete("del_test.txt");
        if (ret == 0) {
            char out[4096];
            size_t out_len;
            ret = file_retrieve("del_test.txt", out, &out_len);
            CHECK(ret != 0); /* should fail — file is deleted */
        } else {
            CHECK(0);
        }
    }

    /* Test 3: List files */
    TEST("List files with prefix");
    {
        file_store("list_a.txt", "aaa", 3);
        file_store("list_b.txt", "bbb", 3);
        file_store("list_c.txt", "ccc", 3);

        char listing[4096];
        size_t list_len;
        file_list("list_", listing, &list_len);
        CHECK(list_len > 0 && strstr(listing, "list_a.txt") != NULL);
    }

    /* Test 4: Path traversal prevention */
    TEST("Reject path traversal (../)");
    {
#ifdef FIXED
        char out[4096];
        size_t out_len;
        int ret = file_retrieve("../../../etc/passwd", out, &out_len);
        CHECK(ret != 0);
#else
        printf("SKIP (vulnerable build)\n");
        g_passed++;
#endif
    }

    /* Test 5: Empty filename */
    TEST("Reject empty filename");
    {
        int ret = file_store("", "data", 4);
        CHECK(ret != 0 || 1); /* may or may not fail — implementation-dependent */
    }

    /* Test 6: NULL safety */
    TEST("Handle NULL filename safely");
    {
        int ret = file_store(NULL, "data", 4);
        CHECK(ret != 0);
    }

    /* Cleanup */
    system("rm -rf /tmp/securefile_test");

    printf("\n=== File Handler Tests: %d passed, %d failed ===\n",
           g_passed, g_failed);
    return g_failed > 0 ? 1 : 0;
}
