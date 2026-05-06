#ifndef FILE_HANDLER_H
#define FILE_HANDLER_H

#include "common.h"

int  file_handler_init(const char *data_dir);
int  file_store(const char *filename, const char *data, size_t data_len);
int  file_retrieve(const char *filename, char *out, size_t *out_len);
int  file_delete(const char *filename);
int  file_list(const char *prefix, char *out, size_t *out_len);

#endif /* FILE_HANDLER_H */
