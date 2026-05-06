#ifndef NETWORK_H
#define NETWORK_H

#include "common.h"

int  network_init(int port);
int  network_accept(void);
int  network_read(int fd, char *buf, size_t len);
int  network_write(int fd, const char *buf, size_t len);
void conn_close(connection_t *conn);

extern connection_t *g_connections[MAX_CONNECTIONS];
extern int           g_conn_count;
extern pthread_mutex_t g_conn_mutex;

#endif /* NETWORK_H */
