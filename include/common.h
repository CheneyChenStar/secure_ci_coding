#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* ── Configuration Constants ─────────────────────────────────────── */

#define MAX_USERNAME_LEN    64
#define MAX_PASSWORD_LEN    128
#define MAX_FILENAME_LEN    256
#define MAX_PATH_LEN        512
#define MAX_CONFIG_LINE     1024
#define SESSION_TOKEN_LEN   64
#define NET_BUFFER_SIZE     4096
#define MAX_CONNECTIONS     32
#define SESSION_TIMEOUT_SEC 1800
#define MAX_PAYLOAD_SIZE    (16 * 1024 * 1024)  /* 16 MB */
#define DEFAULT_PORT        9000
#define USER_DB_MAX         256

/* ── Enums ───────────────────────────────────────────────────────── */

typedef enum {
    ROLE_ADMIN = 0,
    ROLE_USER  = 1,
    ROLE_GUEST = 2
} user_role_t;

typedef enum {
    OP_LOGIN    = 0x0001,
    OP_LOGOUT   = 0x0002,
    OP_UPLOAD   = 0x0003,
    OP_DOWNLOAD = 0x0004,
    OP_DELETE   = 0x0005,
    OP_LIST     = 0x0006,
    OP_BACKUP   = 0x0007
} op_type_t;

typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO  = 1,
    LOG_WARN  = 2,
    LOG_ERROR = 3
} log_level_t;

/* ── Wire Protocol Format (big-endian) ───────────────────────────── */
/*
 * [0..3]   uint32  msg_len     (total message length)
 * [4..5]   uint16  op_code     (operation type)
 * [6..9]   uint32  session_id  (session identifier)
 * [10..13] uint32  data_len    (payload length)
 * [14..]   bytes   data        (variable-length payload)
 */
#define PROTO_HDR_LEN 14

/* ── Structures ──────────────────────────────────────────────────── */

typedef struct {
    int         user_id;
    char        username[MAX_USERNAME_LEN];
    char        password_hash[64];
    user_role_t role;
    int         active;
} user_t;

typedef struct {
    uint32_t    session_id;
    int         user_id;
    user_role_t role;
    char        token[SESSION_TOKEN_LEN];
    time_t      created_at;
    time_t      expires_at;
    int         active;
} session_t;

typedef struct {
    int                 fd;
    struct sockaddr_in  addr;
    char               *buffer;
    size_t              buf_size;
    size_t              buf_used;
    session_t          *session;
} connection_t;

/* ── Utility Macros ──────────────────────────────────────────────── */

#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#define SAFE_FREE(p) do { \
    if ((p)) { free((p)); (p) = NULL; } \
} while (0)

#define UNUSED(x) ((void)(x))

#endif /* COMMON_H */
