#ifndef DDOS_CONFIG_H
#define DDOS_CONFIG_H

#include "common.h"

/* Load configuration from file (JSON) */
config_t *config_load(const char *filename);

/* Free configuration */
void config_free(config_t *config);

/* Reload configuration (hot-reload) */
int config_reload(config_t *config, const char *filename);

/* Validate configuration */
int config_validate(const config_t *config);

/* Get configuration value */
const char *config_get_string(const config_t *config, const char *key);
int config_get_int(const config_t *config, const char *key, int default_val);
bool config_get_bool(const config_t *config, const char *key, bool default_val);

/* Set configuration value */
int config_set_string(config_t *config, const char *key, const char *value);
int config_set_int(config_t *config, const char *key, int value);
int config_set_bool(config_t *config, const char *key, bool value);

/* Save configuration to file */
int config_save(const config_t *config, const char *filename);

#endif /* DDOS_CONFIG_H */
