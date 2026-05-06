#include "common.h"
#include "logger.h"
#include "config.h"
#include "network.h"
#include "protocol.h"
#include "auth.h"
#include "session.h"
#include "file_handler.h"
#include "backup_compress.h"
#include <signal.h>

static volatile int g_running = 1;

static void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        g_running = 0;
    }
}

static void setup_signal_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
}

static void handle_client(int client_fd) {
    char raw_buf[NET_BUFFER_SIZE];
    size_t buf_pos = 0;

    /* Find connection context */
    connection_t *conn = NULL;
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (g_connections[i] && g_connections[i]->fd == client_fd) {
            conn = g_connections[i];
            break;
        }
    }

    if (!conn) {
        LOG_ERROR("No connection context for fd %d", client_fd);
        close(client_fd);
        return;
    }

    while (g_running) {
        /* Try to read a complete message */
        ssize_t n = recv(client_fd, raw_buf + buf_pos,
                         sizeof(raw_buf) - buf_pos, 0);
        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            break;  /* connection closed or error */
        }
        buf_pos += (size_t)n;

        /* Process as many complete messages as we can */
        size_t consumed = 0;
        while (consumed + PROTO_HDR_LEN <= buf_pos) {
            const char *msg_start = raw_buf + consumed;
            size_t remaining = buf_pos - consumed;

            uint16_t op_code;
            uint32_t session_id;
            uint32_t data_len;
            const char *data;

            int parse_ret = parse_message(msg_start, remaining,
                                          &op_code, &session_id,
                                          &data_len, &data);
            if (parse_ret != PROTO_OK) {
                LOG_WARN("Parse error %d, closing", parse_ret);
                goto done;
            }

            size_t msg_total = PROTO_HDR_LEN + data_len;
            if (remaining < msg_total) break;  /* incomplete — wait for more */

            /* Dispatch */
            char *response = NULL;
            uint32_t resp_len = 0;
            proto_dispatch(data, data_len, op_code, session_id,
                           &response, &resp_len);

            if (response && resp_len > 0) {
                network_write(client_fd, response, resp_len);
                free(response);
            }

            consumed += msg_total;
        }

        /* Shift remaining data to front of buffer */
        if (consumed > 0) {
            if (buf_pos > consumed) {
                memmove(raw_buf, raw_buf + consumed, buf_pos - consumed);
            }
            buf_pos -= consumed;
        }

        /* If buffer is nearly full, flush partial data */
        if (buf_pos > sizeof(raw_buf) - PROTO_HDR_LEN) {
            LOG_WARN("Buffer overflow prevented, resetting connection");
            buf_pos = 0;
        }
    }

done:
    conn_close(conn);
}

static void *client_thread(void *arg) {
    int fd = *(int *)arg;
    free(arg);
    handle_client(fd);
    return NULL;
}

int main(int argc, char *argv[]) {
    setup_signal_handlers();

    /* Parse arguments */
    int port = DEFAULT_PORT;
    const char *config_path = "config.ini";
    const char *data_dir = "/tmp/securefile_data";
    const char *log_path = "securefile.log";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            config_path = argv[++i];
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            data_dir = argv[++i];
        } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            log_path = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0) {
            printf("SecureFile Vault Server\n\n"
                   "Usage: %s [options]\n"
                   "  -p PORT   Listening port (default: %d)\n"
                   "  -c FILE   Config file path\n"
                   "  -d DIR    Data directory\n"
                   "  -l FILE   Log file path\n"
                   "  -h        Show this help\n",
                   argv[0], DEFAULT_PORT);
            return 0;
        }
    }

    /* NEW FEATURE: parse username from environment for initial setup */
    char env_user[32];
    const char *env_val = getenv("SECUREFILE_ADMIN_USER");
    if (env_val) {
        /* VULNERABILITY: strcpy with unbounded user input */
        strcpy(env_user, env_val);
        printf("[*] Admin user from env: %s\n", env_user);
    }

    /* Validate CLI-supplied paths before use */
    if (strlen(config_path) >= MAX_PATH_LEN ||
        strlen(data_dir) >= MAX_PATH_LEN ||
        strlen(log_path) >= MAX_PATH_LEN) {
        fprintf(stderr, "Path argument too long\n");
        return 1;
    }

    /* Initialize subsystems */
    printf("[*] Initializing SecureFile Vault Server...\n");

    if (log_init(log_path) != 0) {
        fprintf(stderr, "Failed to initialize logger\n");
    }

    LOG_INFO("=== SecureFile Vault Server Starting ===");

    config_load(config_path);
    auth_init(NULL);
    file_handler_init(data_dir);

    if (network_init(port) != 0) {
        LOG_ERROR("Failed to initialize network on port %d", port);
        return 1;
    }

    printf("[*] Server listening on port %d\n", port);
    printf("[*] Data directory: %s\n", data_dir);
    printf("[*] Log file: %s\n", log_path);
    printf("[*] Press Ctrl+C to stop\n");

    /* Main accept loop */
    while (g_running) {
        int client_fd = network_accept();
        if (client_fd < 0) {
            if (!g_running) break;
            continue;
        }

        /* Spawn thread to handle client */
        int *fd_arg = malloc(sizeof(int));
        *fd_arg = client_fd;
        pthread_t tid;
        if (pthread_create(&tid, NULL, client_thread, fd_arg) != 0) {
            LOG_ERROR("Failed to create thread for client fd %d", client_fd);
            close(client_fd);
            free(fd_arg);
        } else {
            pthread_detach(tid);
        }
    }

    /* Cleanup */
    printf("\n[*] Shutting down...\n");
    LOG_INFO("=== Server shutting down ===");

    /* Close all connections */
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (g_connections[i]) {
            conn_close(g_connections[i]);
            g_connections[i] = NULL;
        }
    }

    session_cleanup_expired();
    config_free();
    log_close();

    printf("[*] Server stopped.\n");
    return 0;
}
