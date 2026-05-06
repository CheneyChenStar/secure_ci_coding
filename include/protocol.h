#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "common.h"

/* Result codes */
#define PROTO_OK            0
#define PROTO_ERR_FORMAT   -1
#define PROTO_ERR_LENGTH   -2
#define PROTO_ERR_OPCODE   -3
#define PROTO_ERR_SESSION  -4
#define PROTO_ERR_AUTH     -5
#define PROTO_ERR_PERM     -6
#define PROTO_ERR_IO       -7

/* Maximum result message length */
#define PROTO_RESULT_MAX    512

/* Dispatch a parsed message and produce a response.
 * Caller owns *response and must free it. */
int proto_dispatch(const char *data, uint32_t data_len,
                   uint16_t op_code, uint32_t session_id,
                   char **response, uint32_t *resp_len);

int parse_message(const char *raw, size_t len,
                  uint16_t *op_code, uint32_t *session_id,
                  uint32_t *data_len, const char **data_start);

int serialize_response(uint16_t op_code, uint32_t session_id,
                       int result_code, const char *result_msg,
                       char *out, size_t *out_len);

#endif /* PROTOCOL_H */
