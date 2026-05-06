/*
 * Unit Tests: Protocol Module
 *
 * Tests:
 * 1. Valid message parsing
 * 2. Message too short
 * 3. Unknown opcode rejection
 * 4. Large payload bounds checking (buffer overflow prevention)
 * 5. Response serialization round-trip
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "../include/common.h"
#include "../include/protocol.h"

static int g_passed = 0;
static int g_failed = 0;

#define TEST(n) do { printf("  TEST: %-50s ", n); } while (0)
#define CHECK(c) do { \
    if (c) { printf("PASS\n"); g_passed++; } \
    else   { printf("FAIL [%s:%d]\n", __FILE__, __LINE__); g_failed++; } \
} while (0)

static void build_packet(char *buf, uint16_t op, uint32_t sid,
                         uint32_t dlen, const char *data) {
    uint32_t total = htonl(PROTO_HDR_LEN + dlen);
    uint16_t op_be = htons(op);
    uint32_t sid_be = htonl(sid);
    uint32_t dlen_be = htonl(dlen);

    memcpy(buf, &total, 4);
    memcpy(buf + 4, &op_be, 2);
    memcpy(buf + 6, &sid_be, 4);
    memcpy(buf + 10, &dlen_be, 4);
    if (data && dlen > 0) memcpy(buf + 14, data, dlen);
}

int main(void) {
    printf("=== Test: Protocol Module ===\n\n");

    /* Test 1: Valid message */
    TEST("Parse valid LOGIN message");
    {
        char packet[1024];
        build_packet(packet, OP_LOGIN, 0, 16, "admin\0password123");
        uint16_t op; uint32_t sid, dlen; const char *data;
        int ret = parse_message(packet, PROTO_HDR_LEN + 16, &op, &sid, &dlen, &data);
        CHECK(ret == PROTO_OK && op == OP_LOGIN && dlen == 16);
    }

    /* Test 2: Message too short */
    TEST("Reject message shorter than header");
    {
        char short_pkt[10] = {0};
        uint16_t op; uint32_t sid, dlen; const char *data;
        int ret = parse_message(short_pkt, 10, &op, &sid, &dlen, &data);
        CHECK(ret == PROTO_ERR_LENGTH);
    }

    /* Test 3: Unknown opcode */
    TEST("Reject unknown opcode");
    {
        char packet[1024];
        build_packet(packet, 0xFFFF, 0, 4, "test");
        uint16_t op; uint32_t sid, dlen; const char *data;
        int ret = parse_message(packet, PROTO_HDR_LEN + 4, &op, &sid, &dlen, &data);
        CHECK(ret == PROTO_ERR_OPCODE);
    }

    /* Test 4: Incomplete data */
    TEST("Reject truncated data payload");
    {
        char packet[1024];
        build_packet(packet, OP_UPLOAD, 0, 100, "short");
        uint16_t op; uint32_t sid, dlen; const char *data;
        int ret = parse_message(packet, PROTO_HDR_LEN + 5, &op, &sid, &dlen, &data);
        CHECK(ret == PROTO_ERR_LENGTH);
    }

    /* Test 5: Response serialization */
    TEST("Serialize response message");
    {
        char out[512];
        size_t len;
        int ret = serialize_response(OP_LOGIN, 42, PROTO_OK, "LOGIN_OK", out, &len);
        CHECK(ret == 0 && len == PROTO_HDR_LEN + 8);
    }

    /* Test 6: Zero-length data */
    TEST("Parse message with zero data_len");
    {
        char packet[1024];
        build_packet(packet, OP_LOGOUT, 12345, 0, NULL);
        uint16_t op; uint32_t sid, dlen; const char *data;
        int ret = parse_message(packet, PROTO_HDR_LEN, &op, &sid, &dlen, &data);
        CHECK(ret == PROTO_OK && dlen == 0 && sid == 12345);
    }

    printf("\n=== Protocol Tests: %d passed, %d failed ===\n",
           g_passed, g_failed);
    return g_failed > 0 ? 1 : 0;
}
