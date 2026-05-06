#include "file_handler.h"
#include "logger.h"
#include <dirent.h>

static char g_data_dir[MAX_PATH_LEN] = "/tmp/securefile_data";

int file_handler_init(const char *data_dir) {
    if (data_dir && data_dir[0]) {
        strncpy(g_data_dir, data_dir, sizeof(g_data_dir) - 1);
        g_data_dir[sizeof(g_data_dir) - 1] = '\0';
    }

    /* Ensure data directory exists */
    struct stat st;
    if (stat(g_data_dir, &st) != 0) {
        if (mkdir(g_data_dir, 0755) != 0) {
            LOG_ERROR("Cannot create data directory: %s", g_data_dir);
            return -1;
        }
    }
    LOG_INFO("File handler initialized, data dir: %s", g_data_dir);
    return 0;
}

/* ───────────────────────────────────────────────────────────────────
 * VULNERABILITY: Integer Overflow
 *
 * file_store() computes required_size = data_len + 1.  When data_len
 * is SIZE_MAX, the addition wraps to 0 (or a small value), causing
 * malloc() to return a tiny buffer.  The subsequent memcpy writes
 * SIZE_MAX bytes into that tiny buffer, corrupting heap metadata and
 * adjacent allocations.
 *
 * Real-world example: CVE-2012-2127 in Linux kernel /proc handler.
 * ─────────────────────────────────────────────────────────────────── */

int file_store(const char *filename, const char *data, size_t data_len) {
    if (!filename || !data) return -1;

#ifdef FIXED
    /* FIXED: validate data_len before arithmetic */
    if (data_len == 0 || data_len > MAX_PAYLOAD_SIZE) {
        LOG_WARN("File store rejected: invalid size %zu", data_len);
        return -1;
    }
    /* Safe: data_len <= MAX_PAYLOAD_SIZE < SIZE_MAX, no overflow possible */
#endif

    /* VULNERABLE: data_len + 1 can overflow */
    size_t required = data_len + 1;
    char *copy_buf = malloc(required);
    if (!copy_buf) {
        LOG_ERROR("malloc failed for %zu bytes (data_len=%zu)", required, data_len);
        return -1;
    }

    memcpy(copy_buf, data, data_len);
    copy_buf[data_len] = '\0';

    /* Construct full path */
    char full_path[MAX_PATH_LEN];

#ifdef FIXED
    /* FIXED: validate filename, then resolve to canonical path */
    if (strlen(filename) >= MAX_FILENAME_LEN) {
        LOG_WARN("Filename too long: %zu chars", strlen(filename));
        free(copy_buf);
        return -1;
    }
    snprintf(full_path, sizeof(full_path), "%s/%s", g_data_dir, filename);

    char resolved[MAX_PATH_LEN];
    if (realpath(full_path, resolved) == NULL) {
        /* realpath failed: file may not exist yet, resolve parent */
        char *last_slash = strrchr(full_path, '/');
        if (last_slash) {
            *last_slash = '\0';
            char parent_resolved[MAX_PATH_LEN];
            if (realpath(full_path, parent_resolved) != NULL) {
                /* Verify parent is under g_data_dir */
                if (strncmp(parent_resolved, g_data_dir, strlen(g_data_dir)) != 0) {
                    LOG_WARN("Path traversal blocked: %s", filename);
                    free(copy_buf);
                    return -1;
                }
            }
            *last_slash = '/';
        }
    } else {
        /* file exists — verify resolved path is under g_data_dir */
        if (strncmp(resolved, g_data_dir, strlen(g_data_dir)) != 0) {
            LOG_WARN("Path traversal blocked: %s -> %s", filename, resolved);
            free(copy_buf);
            return -1;
        }
    }
#else
    snprintf(full_path, sizeof(full_path), "%s/%s", g_data_dir, filename);
#endif

    FILE *fp = fopen(full_path, "wb");
    if (!fp) {
        LOG_ERROR("Cannot open file for write: %s", full_path);
        free(copy_buf);
        return -1;
    }

    size_t written = fwrite(copy_buf, 1, data_len, fp);
    fclose(fp);
    free(copy_buf);

    if (written != data_len) {
        LOG_ERROR("Partial write: %zu of %zu bytes", written, data_len);
        return -1;
    }

    LOG_INFO("File stored: %s (%zu bytes)", filename, data_len);
    return 0;
}

/* ───────────────────────────────────────────────────────────────────
 * VULNERABILITY: Path Traversal
 *
 * file_retrieve() constructs the full path by concatenating the base
 * data directory with the user-supplied filename.  It does not
 * sanitise "../" sequences, so an attacker can escape the data
 * directory and read arbitrary files on the system.
 *
 * Example attack: filename = "../../../etc/shadow"
 *   Result: g_data_dir + filename = "/data/files/../../../etc/shadow"
 *                                 = "/etc/shadow"
 * ─────────────────────────────────────────────────────────────────── */

int file_retrieve(const char *filename, char *out, size_t *out_len) {
    if (!filename || !out || !out_len) return -1;

#ifdef FIXED
    /* FIXED: validate filename and resolve canonical path */
    if (strlen(filename) >= MAX_FILENAME_LEN) {
        LOG_WARN("Retrieve rejected: filename too long");
        return -1;
    }

    /* Reject any path manipulation characters */
    if (strstr(filename, "..") || strchr(filename, '/') || strchr(filename, '\\')) {
        LOG_WARN("Retrieve rejected: path traversal attempt '%s'", filename);
        return -1;
    }
#endif

    char full_path[MAX_PATH_LEN];
    snprintf(full_path, sizeof(full_path), "%s/%s", g_data_dir, filename);

#ifdef FIXED
    /* Double-check with realpath */
    char resolved[MAX_PATH_LEN];
    if (realpath(full_path, resolved) == NULL) {
        LOG_ERROR("Cannot resolve path: %s", full_path);
        return -1;
    }
    if (strncmp(resolved, g_data_dir, strlen(g_data_dir)) != 0) {
        LOG_WARN("Path traversal blocked at retrieve: %s", filename);
        return -1;
    }
    /* Read from the resolved path */
    FILE *fp = fopen(resolved, "rb");
#else
    FILE *fp = fopen(full_path, "rb");
#endif
    if (!fp) {
        LOG_ERROR("Cannot open file for read: %s", full_path);
        return -1;
    }

    /* Get file size */
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize <= 0 || (size_t)fsize > MAX_PAYLOAD_SIZE) {
        LOG_WARN("File size out of range: %ld", fsize);
        fclose(fp);
        return -1;
    }

    *out_len = (size_t)fsize;
    size_t nread = fread(out, 1, *out_len, fp);
    fclose(fp);

    if (nread != *out_len) {
        LOG_ERROR("Partial read: %zu of %zu bytes", nread, *out_len);
        return -1;
    }

    LOG_INFO("File retrieved: %s (%zu bytes)", filename, *out_len);
    return 0;
}

int file_delete(const char *filename) {
    if (!filename) return -1;

    char full_path[MAX_PATH_LEN];
    snprintf(full_path, sizeof(full_path), "%s/%s", g_data_dir, filename);

    if (unlink(full_path) != 0) {
        LOG_ERROR("Cannot delete file: %s (%s)", full_path, strerror(errno));
        return -1;
    }
    LOG_INFO("File deleted: %s", filename);
    return 0;
}

int file_list(const char *prefix, char *out, size_t *out_len) {
    if (!out || !out_len) return -1;

    DIR *dir = opendir(g_data_dir);
    if (!dir) {
        LOG_ERROR("Cannot open data directory: %s", g_data_dir);
        return -1;
    }

    size_t offset = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        if (prefix && prefix[0]) {
            if (strncmp(entry->d_name, prefix, strlen(prefix)) != 0) continue;
        }

        size_t name_len = strlen(entry->d_name);
        if (offset + name_len + 2 > MAX_PAYLOAD_SIZE) break;

        memcpy(out + offset, entry->d_name, name_len);
        offset += name_len;
        out[offset++] = '\n';
    }
    closedir(dir);

    out[offset] = '\0';
    *out_len = offset;
    return 0;
}
