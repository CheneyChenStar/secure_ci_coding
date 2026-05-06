/*
 * VULNERABILITY: Buffer Overflow (CWE-120)
 *
 * This demo simulates a network protocol parser that copies a variable-length
 * payload into a fixed-size stack buffer without bounds checking.
 *
 * PRINCIPLE: When the attacker controls data_len, they can overflow 'filename'
 * on the stack and overwrite the return address.
 *
 * IMPACT: Remote Code Execution (RCE) — attacker gains shell on the server.
 *
 * To compile: gcc -o vuln_bof 01_buffer_overflow.c
 * To exploit: echo -n $'\x00\x00\x00\xFFAAAAAAAAAA...' | ./vuln_bof
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define FILENAME_MAX 32   /* too small — easily overflowed */
#define HDR_SIZE     14

static int parse_message(const char *raw, size_t len) {
    uint32_t data_len;

    if (len < HDR_SIZE) {
        printf("[-] Message too short\n");
        return -1;
    }

    /* Simulate reading data_len from network header (big-endian) */
    memcpy(&data_len, raw + 10, 4);

    printf("[*] Received data_len = %u\n", data_len);

    /* VULNERABILITY: data_len is attacker-controlled, not checked against
     * the size of the fixed buffer below */
    if (data_len > 1024) {
        printf("[-] data_len too large: %u\n", data_len);
        return -1;
    }

    {
        char filename[FILENAME_MAX];
        const char *payload = raw + HDR_SIZE;

        printf("[*] Copying %u bytes into %zu-byte buffer\n",
               data_len, sizeof(filename));

        /* THE BUG: memcpy with attacker-controlled size, no bounds check
         * against the destination buffer */
        memcpy(filename, payload, data_len);

        printf("[+] Filename: %s\n", filename);
    }

    /* If data_len > 32, the return address is already corrupted.
     * On return from parse_message(), execution jumps to attacker's address.
     */
    return 0;
}

int main(int argc, char *argv[]) {
    char packet[1080];

    printf("=== CWE-120: Buffer Overflow Demo ===\n\n");

    if (argc > 1) {
        /* Read payload from argument (simulating network data) */
        size_t payload_len = strlen(argv[1]);
        if (payload_len > 1024) payload_len = 1024;

        memset(packet, 0, sizeof(packet));
        /* msg_len */     packet[3] = (payload_len + 14) & 0xFF;
        /* op_code */     packet[5] = 0x03;  // OP_UPLOAD
        /* session_id */  packet[9] = 0x01;
        /* data_len */    memcpy(packet + 10, &payload_len, 4);
        /* data */        memcpy(packet + 14, argv[1], payload_len);

        printf("[*] Simulating incoming packet (%zu bytes payload)\n", payload_len);
        parse_message(packet, 14 + payload_len);
    } else {
        /* Demonstrate with a safe example */
        printf("[*] Safe demo (8-byte payload):\n");
        memset(packet, 0, sizeof(packet));
        uint32_t safe_len = 8;
        memcpy(packet + 10, &safe_len, 4);
        memcpy(packet + 14, "test.txt", 8);
        parse_message(packet, 14 + 8);

        printf("\n[*] To trigger overflow, run:\n");
        printf("    ./vuln_bof \"$(python3 -c 'print(\"A\"*64)')\"\n");
        printf("    This writes 64 bytes into a 32-byte buffer.\n");
    }

    return 0;
}
