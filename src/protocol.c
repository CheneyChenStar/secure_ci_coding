#include "protocol.h"
#include "logger.h"
#include "auth.h"
#include "session.h"
#include "file_handler.h"
#include "config.h"

#include <arpa/inet.h>

/* ───────────────────────────────────────────────────────────────────
 * VULNERABILITY: Buffer Overflow
 *
 * parse_message() copies a variable-length network payload into
 * fixed-size stack buffers without validating the length against
 * the destination buffer size.  An attacker who sends data_len
 * larger than the internal buffer can overwrite the return address
 * and other stack data, achieving remote code execution.
 *
 * The raw protocol header is 14 bytes, followed by data_len bytes.
 * Attack: data_len > MAX_FILENAME_LEN overflows stack buffer.
 * ─────────────────────────────────────────────────────────────────── */

int parse_message(const char *raw, size_t len,
                  uint16_t *op_code, uint32_t *session_id,
                  uint32_t *data_len, const char **data_start) {

    if (len < PROTO_HDR_LEN) {
        LOG_WARN("Message too short: %zu bytes", len);
        return PROTO_ERR_LENGTH;
    }

    /* Parse fixed header fields (big-endian) */
    uint32_t msg_len_be;
    memcpy(&msg_len_be, raw, 4);
    uint32_t msg_len = ntohl(msg_len_be);
    UNUSED(msg_len);  /* msg_len validated indirectly by data_len + len check */

    uint16_t op_code_be;
    memcpy(&op_code_be, raw + 4, 2);
    *op_code = ntohs(op_code_be);

    uint32_t session_id_be;
    memcpy(&session_id_be, raw + 6, 4);
    *session_id = ntohl(session_id_be);

    uint32_t data_len_be;
    memcpy(&data_len_be, raw + 10, 4);
    *data_len = ntohl(data_len_be);

    if (len < PROTO_HDR_LEN + *data_len) {
        LOG_WARN("Incomplete message: header=%d data=%u received=%zu",
                 PROTO_HDR_LEN, *data_len, len);
        return PROTO_ERR_LENGTH;
    }

    *data_start = raw + PROTO_HDR_LEN;

    /* ── VALIDATE op_code ─────────────────────────────────── */
    switch (*op_code) {
    case OP_LOGIN:
    case OP_LOGOUT:
    case OP_UPLOAD:
    case OP_DOWNLOAD:
    case OP_DELETE:
    case OP_LIST:
    case OP_BACKUP:
        break;
    default:
        LOG_WARN("Unknown op_code: 0x%04x", *op_code);
        return PROTO_ERR_OPCODE;
    }

    return PROTO_OK;
}

/* ───────────────────────────────────────────────────────────────────
 * proto_dispatch — process a parsed message and produce a response.
 *
 * This function contains the buffer overflow vulnerability:
 * When handling UPLOAD/DOWNLOAD/DELETE operations, the filename
 * is copied from the network buffer into a fixed-size stack buffer
 * (char filename[MAX_FILENAME_LEN]) without checking data_len.
 * ─────────────────────────────────────────────────────────────────── */
int proto_dispatch(const char *data, uint32_t data_len,
                   uint16_t op_code, uint32_t session_id,
                   char **response, uint32_t *resp_len) {

    char result_msg[PROTO_RESULT_MAX] = {0};
    int  result_code = PROTO_OK;
    char *resp_data = NULL;
    uint32_t resp_data_len = 0;

    /* Look up session for operations that need it */
    session_t *session = NULL;
    if (op_code != OP_LOGIN) {
        session = session_lookup(session_id);
        if (!session) {
            result_code = PROTO_ERR_SESSION;
            snprintf(result_msg, sizeof(result_msg), "Invalid or expired session");
            goto respond;
        }
        if (!session_validate(session)) {
            result_code = PROTO_ERR_SESSION;
            snprintf(result_msg, sizeof(result_msg), "Session expired, please re-login");
            goto respond;
        }
    }

    switch (op_code) {

    case OP_LOGIN: {
        /* data = "username\0password" */
        if (data_len < 2 || data_len > MAX_USERNAME_LEN + MAX_PASSWORD_LEN + 2) {
            result_code = PROTO_ERR_AUTH;
            snprintf(result_msg, sizeof(result_msg), "Invalid login payload size");
            break;
        }

#ifdef FIXED
        char username[MAX_USERNAME_LEN];
        char password[MAX_PASSWORD_LEN];
#endif
        const char *user_start = data;
        const char *pw_start = memchr(data, '\0', data_len);
        if (!pw_start) {
            result_code = PROTO_ERR_AUTH;
            snprintf(result_msg, sizeof(result_msg), "Malformed login data");
            break;
        }
        pw_start++;

        /* VULNERABLE: no length check before copy */
#ifdef FIXED
        size_t user_len = pw_start - user_start - 1;
        if (user_len >= MAX_USERNAME_LEN) user_len = MAX_USERNAME_LEN - 1;
        memcpy(username, user_start, user_len);
        username[user_len] = '\0';

        size_t pw_len = data_len - (pw_start - data);
        if (pw_len >= MAX_PASSWORD_LEN) pw_len = MAX_PASSWORD_LEN - 1;
        memcpy(password, pw_start, pw_len);
        password[pw_len] = '\0';

        if (!auth_verify(username, password)) {
#else
        if (!auth_verify(user_start, pw_start)) {
#endif
            result_code = PROTO_ERR_AUTH;
            snprintf(result_msg, sizeof(result_msg), "Authentication failed");
            break;
        }

        user_t *user = auth_lookup_user(user_start);
        char token[SESSION_TOKEN_LEN];
        uint32_t new_sid = session_create(user ? user->user_id : -1,
                                          user ? user->role : ROLE_GUEST,
                                          token);
        snprintf(result_msg, sizeof(result_msg),
                 "LOGIN_OK %u %s", new_sid, token);
        LOG_INFO("User logged in, session=%u", new_sid);
        break;
    }

    case OP_LOGOUT: {
        session_destroy(session_id);
        snprintf(result_msg, sizeof(result_msg), "LOGOUT_OK");
        LOG_INFO("Session %u logged out", session_id);
        break;
    }

    case OP_UPLOAD: {
        /* data = "filename\0file_content" */
        const char *fn_end = memchr(data, '\0', data_len);
        if (!fn_end) {
            result_code = PROTO_ERR_FORMAT;
            snprintf(result_msg, sizeof(result_msg), "Missing filename in upload");
            break;
        }

        const char *filename = data;
        size_t fn_len = (size_t)(fn_end - data);
        const char *file_data = fn_end + 1;
        size_t file_data_len = data_len - fn_len - 1;

        /* VULNERABLE: no bounds check on filename copy */
#ifdef FIXED
        char safe_fn[MAX_FILENAME_LEN];
        size_t copy_len = (fn_len >= MAX_FILENAME_LEN) ? (MAX_FILENAME_LEN - 1) : fn_len;
        memcpy(safe_fn, filename, copy_len);
        safe_fn[copy_len] = '\0';

        /* Validate against path traversal */
        if (strstr(safe_fn, "..") || strchr(safe_fn, '/')) {
            result_code = PROTO_ERR_PERM;
            snprintf(result_msg, sizeof(result_msg), "Invalid filename characters");
            break;
        }

        if (file_data_len > MAX_PAYLOAD_SIZE) {
            result_code = PROTO_ERR_LENGTH;
            snprintf(result_msg, sizeof(result_msg), "File too large");
            break;
        }

        if (file_store(safe_fn, file_data, file_data_len) != 0) {
#else
        if (file_store(filename, file_data, file_data_len) != 0) {
#endif
            result_code = PROTO_ERR_IO;
            snprintf(result_msg, sizeof(result_msg), "File storage failed");
        } else {
            snprintf(result_msg, sizeof(result_msg), "UPLOAD_OK");
            LOG_INFO("File uploaded: %s (%zu bytes)", filename, file_data_len);
        }
        break;
    }

    case OP_DOWNLOAD: {
        /* data = "filename" */
        size_t data_out_len = 0;

#ifdef FIXED
        char filename[MAX_FILENAME_LEN];
        size_t copy_len = (data_len >= MAX_FILENAME_LEN) ? (MAX_FILENAME_LEN - 1) : data_len;
        memcpy(filename, data, copy_len);
        filename[copy_len] = '\0';

        if (strstr(filename, "..") || strchr(filename, '/')) {
            result_code = PROTO_ERR_PERM;
            snprintf(result_msg, sizeof(result_msg), "Invalid filename characters");
            break;
        }

        char *file_content = malloc(MAX_PAYLOAD_SIZE);
        if (!file_content) {
            result_code = PROTO_ERR_IO;
            snprintf(result_msg, sizeof(result_msg), "Memory allocation failed");
            break;
        }

        int ret = file_retrieve(filename, file_content, &data_out_len);
#else
        char *file_content = malloc(MAX_PAYLOAD_SIZE);
        if (!file_content) {
            result_code = PROTO_ERR_IO;
            snprintf(result_msg, sizeof(result_msg), "Memory allocation failed");
            break;
        }

        int ret = file_retrieve(data, file_content, &data_out_len);
#endif
        if (ret != 0) {
            free(file_content);
            result_code = PROTO_ERR_IO;
            snprintf(result_msg, sizeof(result_msg), "File not found or read error");
        } else {
            resp_data = file_content;
            resp_data_len = (uint32_t)data_out_len;
            snprintf(result_msg, sizeof(result_msg), "DOWNLOAD_OK");
            LOG_INFO("File downloaded: %s (%zu bytes)", data, data_out_len);
        }
        break;
    }

    case OP_DELETE: {
        if (session->role != ROLE_ADMIN) {
            result_code = PROTO_ERR_PERM;
            snprintf(result_msg, sizeof(result_msg), "Admin permission required for delete");
            break;
        }

        int ret = file_delete(data);
        if (ret != 0) {
            result_code = PROTO_ERR_IO;
            snprintf(result_msg, sizeof(result_msg), "Delete failed");
        } else {
            snprintf(result_msg, sizeof(result_msg), "DELETE_OK");
            LOG_INFO("File deleted: %s", data);
        }
        break;
    }

    case OP_LIST: {
        size_t list_len = 0;
        char *listing = malloc(MAX_PAYLOAD_SIZE);
        if (!listing) {
            result_code = PROTO_ERR_IO;
            snprintf(result_msg, sizeof(result_msg), "Memory allocation failed");
            break;
        }

        file_list(data_len > 0 ? data : "", listing, &list_len);
        resp_data = listing;
        resp_data_len = (uint32_t)list_len;
        snprintf(result_msg, sizeof(result_msg), "LIST_OK");
        break;
    }

    case OP_BACKUP: {
        if (session->role != ROLE_ADMIN) {
            result_code = PROTO_ERR_PERM;
            snprintf(result_msg, sizeof(result_msg), "Admin permission required for backup");
            break;
        }
        config_backup(data);
        snprintf(result_msg, sizeof(result_msg), "BACKUP_OK");
        break;
    }

    default:
        result_code = PROTO_ERR_OPCODE;
        snprintf(result_msg, sizeof(result_msg), "Unhandled operation");
        break;
    }

respond: {
        size_t resp_buf_size = PROTO_HDR_LEN + PROTO_RESULT_MAX + resp_data_len;
        char *resp_buf = malloc(resp_buf_size);
        if (!resp_buf) {
            free(resp_data);
            return PROTO_ERR_IO;
        }

        size_t serialized_len = 0;
        serialize_response(op_code, session_id, result_code, result_msg,
                           resp_buf, &serialized_len);

        /* Append file data for downloads / listings */
        if (resp_data && resp_data_len > 0) {
            memcpy(resp_buf + serialized_len, resp_data, resp_data_len);
            serialized_len += resp_data_len;
        }

        free(resp_data);
        *response = resp_buf;
        *resp_len = (uint32_t)serialized_len;
        return result_code;
    }
}

int serialize_response(uint16_t op_code, uint32_t session_id,
                       int result_code, const char *result_msg,
                       char *out, size_t *out_len) {
    UNUSED(result_code);

    size_t msg_len = strlen(result_msg);
    if (msg_len >= PROTO_RESULT_MAX) msg_len = PROTO_RESULT_MAX - 1;

    uint32_t total_len = PROTO_HDR_LEN + (uint32_t)msg_len;
    uint32_t total_be = htonl(total_len);
    uint16_t op_be = htons(op_code);
    uint32_t sid_be = htonl(session_id);
    uint32_t data_be = htonl((uint32_t)msg_len);

    memcpy(out, &total_be, 4);
    memcpy(out + 4, &op_be, 2);
    memcpy(out + 6, &sid_be, 4);
    memcpy(out + 10, &data_be, 4);
    memcpy(out + 14, result_msg, msg_len);

    *out_len = total_len;
    return 0;
}
