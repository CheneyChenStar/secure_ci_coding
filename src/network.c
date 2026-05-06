#include "network.h"
#include "logger.h"

static int g_listen_fd = -1;

connection_t *g_connections[MAX_CONNECTIONS] = {0};
int           g_conn_count = 0;
pthread_mutex_t g_conn_mutex = PTHREAD_MUTEX_INITIALIZER;

int network_init(int port) {
    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_fd < 0) {
        LOG_ERROR("Socket creation failed: %s", strerror(errno));
        return -1;
    }

    int opt = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);

    if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("Bind failed on port %d: %s", port, strerror(errno));
        close(g_listen_fd);
        return -1;
    }

    if (listen(g_listen_fd, 10) < 0) {
        LOG_ERROR("Listen failed: %s", strerror(errno));
        close(g_listen_fd);
        return -1;
    }

    LOG_INFO("Server listening on port %d", port);
    return 0;
}

int network_accept(void) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    int client_fd = accept(g_listen_fd, (struct sockaddr *)&client_addr, &addr_len);
    if (client_fd < 0) {
        if (errno != EINTR) {
            LOG_ERROR("Accept failed: %s", strerror(errno));
        }
        return -1;
    }

    connection_t *conn = calloc(1, sizeof(connection_t));
    if (!conn) {
        close(client_fd);
        return -1;
    }

    conn->fd = client_fd;
    conn->addr = client_addr;
    conn->buf_size = NET_BUFFER_SIZE;
    conn->buffer = malloc(conn->buf_size);
    if (!conn->buffer) {
        free(conn);
        close(client_fd);
        return -1;
    }
    conn->buf_used = 0;
    conn->session = NULL;

    pthread_mutex_lock(&g_conn_mutex);
    if (g_conn_count < MAX_CONNECTIONS) {
        g_connections[g_conn_count++] = conn;
    } else {
        pthread_mutex_unlock(&g_conn_mutex);
        free(conn->buffer);
        free(conn);
        close(client_fd);
        LOG_WARN("Max connections reached, rejecting %s:%d",
                 inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        return -1;
    }
    pthread_mutex_unlock(&g_conn_mutex);

    LOG_INFO("New connection from %s:%d (fd=%d)",
             inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), client_fd);
    return client_fd;
}

int network_read(int fd, char *buf, size_t len) {
    ssize_t n = recv(fd, buf, len, 0);
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOG_ERROR("Read error on fd %d: %s", fd, strerror(errno));
        }
        return -1;
    }
    return (int)n;
}

int network_write(int fd, const char *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = send(fd, buf + total, len - total, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            LOG_ERROR("Write error on fd %d: %s", fd, strerror(errno));
            return -1;
        }
        total += (size_t)n;
    }
    return 0;
}

/* ───────────────────────────────────────────────────────────────────
 * VULNERABILITY: Double Free
 *
 * The error path at check_session frees conn->buffer and then jumps
 * to cleanup, where conn->buffer is freed again.  This corrupts the
 * heap allocator metadata and can lead to arbitrary write primitives.
 *
 * The vulnerable code path:
 *   1. Normal execution frees buffer at cleanup label
 *   2. Error in between also frees buffer → second free of same pointer
 * ─────────────────────────────────────────────────────────────────── */
void conn_close(connection_t *conn) {
    if (!conn) return;

    LOG_INFO("Closing connection fd=%d", conn->fd);

#ifdef FIXED
    /* FIXED: free once and set to NULL, making second free a safe no-op */
    SAFE_FREE(conn->buffer);
    if (conn->fd > 0) {
        close(conn->fd);
        conn->fd = -1;
    }
    SAFE_FREE(conn);
#else
    /* VULNERABLE: potential double free in specific error paths */
    if (conn->session) {
        /* Simulated: shutdown write half, if it fails we jump to cleanup
         * which also frees conn->buffer */
        if (shutdown(conn->fd, SHUT_WR) < 0) {
            LOG_WARN("Shutdown failed for fd %d", conn->fd);
            free(conn->buffer);  /* first free — BUG: no NULL assignment */
            goto cleanup;
        }
    }

    if (conn->buffer) {
        free(conn->buffer);
    }
    if (conn->fd > 0) {
        close(conn->fd);
    }

cleanup:
    /* BUG: if we jumped here, conn->buffer was already freed above
     * but still holds a non-NULL dangling pointer */
    free(conn->buffer);  /* double free! */
    free(conn);
#endif
}
