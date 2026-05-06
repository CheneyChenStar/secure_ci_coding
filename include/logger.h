#ifndef LOGGER_H
#define LOGGER_H

#include "common.h"

int  log_init(const char *log_path);
void log_write(log_level_t level, const char *format, ...);
void log_close(void);

/* Convenience macros — note: these invoke log_write which contains
 * a format-string vulnerability in the vulnerable build. */
#define LOG_DEBUG(fmt, ...) log_write(LOG_DEBUG, (fmt), ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  log_write(LOG_INFO,  (fmt), ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  log_write(LOG_WARN,  (fmt), ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) log_write(LOG_ERROR, (fmt), ##__VA_ARGS__)

#endif /* LOGGER_H */
