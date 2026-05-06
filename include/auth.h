#ifndef AUTH_H
#define AUTH_H

#include "common.h"

int  auth_init(const char *user_db_path);
int  auth_verify(const char *username, const char *password);
void auth_hash_password(const char *password, char *hash_out);
int  auth_create_user(const char *username, const char *password, user_role_t role);
int  auth_user_exists(const char *username);
user_t *auth_lookup_user(const char *username);

extern user_t g_user_db[USER_DB_MAX];
extern int    g_user_count;

#endif /* AUTH_H */
