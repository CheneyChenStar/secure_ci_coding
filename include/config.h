#ifndef CONFIG_H
#define CONFIG_H

#include "common.h"

int   config_load(const char *config_path);
char *config_get(const char *key, const char *default_val);
int   config_get_int(const char *key, int default_val);
void  config_backup(const char *dest_path);
void  config_free(void);

#endif /* CONFIG_H */
