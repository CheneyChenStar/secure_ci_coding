/*
 * FIXED: Buffer Overflow (CWE-120)
 *
 * Fixes applied:
 * 1. Validate data_len against destination buffer size BEFORE memcpy
 * 2. Use strncpy-style bounded copy with explicit NUL termination
 * 3. Reject oversized payloads rather than truncating silently
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define FILENAME_MAX 32
#define HDR_SIZE     14

static int parse_message(const char *raw, size_t len) {
    uint32_t data_len;

    if (len < HDR_SIZE) {
        printf("[-] Message too short\n");
        return -1;
    }

    memcpy(&data_len, raw + 10, 4);

    printf("[*] Received data_len = %u\n", data_len);

    /* FIX 1: validate against destination buffer size */
    if (data_len >= FILENAME_MAX) {
        printf("[-] data_len %u exceeds max filename length %d\n",
               data_len, FILENAME_MAX - 1);
        return -1;
    }

    /* FIX 2: also validate against total message size */
    if (len < HDR_SIZE + data_len) {
        printf("[-] Incomplete message\n");
        return -1;
    }

    {
        char filename[FILENAME_MAX];
        const char *payload = raw + HDR_SIZE;

        printf("[*] Copying %u bytes into %zu-byte buffer (safe)\n",
               data_len, sizeof(filename));

        /* FIX 3: bounded copy with explicit NUL termination */
        memcpy(filename, payload, data_len);
        filename[data_len] = '\0';

        printf("[+] Filename: %s\n", filename);
    }

    return 0;
}

int main(int argc, char *argv[]) {
    char packet[1080];

    printf("=== CWE-120: Buffer Overflow — FIXED ===\n\n");

    if (argc > 1) {
        size_t payload_len = strlen(argv[1]);
        if (payload_len > 1024) payload_len = 1024;

        memset(packet, 0, sizeof(packet));
        packet[3] = (payload_len + 14) & 0xFF;
        packet[5] = 0x03;
        packet[9] = 0x01;
        memcpy(packet + 10, &payload_len, 4);
        memcpy(packet + 14, argv[1], payload_len);

        parse_message(packet, 14 + payload_len);
    } else {
        printf("[*] Safe test (8-byte payload):\n");
        memset(packet, 0, sizeof(packet));
        uint32_t safe_len = 8;
        memcpy(packet + 10, &safe_len, 4);
        memcpy(packet + 14, "test.txt", 8);
        parse_message(packet, 14 + 8);

        printf("\n[*] Attack attempt (64-byte payload for 32-byte buffer):\n");
        memset(packet, 0, sizeof(packet));
        uint32_t attack_len = 64;
        memcpy(packet + 10, &attack_len, 4);
        memset(packet + 14, 'A', 64);
        parse_message(packet, 14 + 64);
        printf("    ^^- Correctly REJECTED (no overflow)\n");
    }

    return 0;
}
