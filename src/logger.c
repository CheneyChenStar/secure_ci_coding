#include "logger.h"
#include <stdarg.h>

static FILE *g_log_fp = NULL;

int log_init(const char *log_path) {
    g_log_fp = fopen(log_path, "a");
    if (!g_log_fp) {
        g_log_fp = stderr;
        return -1;
    }
    return 0;
}

/* VULNERABILITY: Format String
 *
 * In the vulnerable build, when callers pass user-controlled strings
 * as the 'format' parameter, the data is interpreted as a format string
 * rather than a plain string value.  This allows attackers to read
 * stack memory (%x, %p) or write to arbitrary addresses (%n).
 *
 * Safe usage:  log_write(LOG_INFO, "%s", user_data);
 * Unsafe usage: log_write(LOG_INFO, user_data);
 */
void log_write(log_level_t level, const char *format, ...) {
    if (!g_log_fp) g_log_fp = stderr;

    const char *level_str;
    switch (level) {
    case LOG_DEBUG: level_str = "DEBUG"; break;
    case LOG_INFO:  level_str = "INFO";  break;
    case LOG_WARN:  level_str = "WARN";  break;
    case LOG_ERROR: level_str = "ERROR"; break;
    default:        level_str = "????";  break;
    }

    time_t now = time(NULL);
    struct tm tm_buf;
    struct tm *tm_info = localtime_r(&now, &tm_buf);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(g_log_fp, "[%s] [%s] ", time_buf, level_str);

    va_list args;
    va_start(args, format);

#ifdef FIXED
    /* FIXED: pass user data as a variadic argument, not as the format */
    fprintf(g_log_fp, "%s", format);
    (void)args;
#else
    /* VULNERABLE: user-controlled string used directly as format */
    vfprintf(g_log_fp, format, args);
#endif
    va_end(args);

    fprintf(g_log_fp, "\n");
    fflush(g_log_fp);
}

void log_close(void) {
    if (g_log_fp && g_log_fp != stderr) {
        fclose(g_log_fp);
        g_log_fp = NULL;
    }
}
