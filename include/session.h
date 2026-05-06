#ifndef SESSION_H
#define SESSION_H

#include "common.h"

uint32_t    session_create(int user_id, user_role_t role, char *token_out);
session_t  *session_lookup(uint32_t session_id);
int         session_validate(session_t *s);
void        session_destroy_by_ptr(session_t *s);
void        session_destroy(uint32_t session_id);
void        session_cleanup_expired(void);

extern session_t *g_sessions[MAX_CONNECTIONS];
extern int        g_session_count;
extern pthread_mutex_t g_session_mutex;

#endif /* SESSION_H */
