#ifndef DDOS_LOGGER_H
#define DDOS_LOGGER_H

#include <stdarg.h>
#include <syslog.h>

/* Log levels */
typedef enum {
	LOG_LEVEL_DEBUG = 0,
	LOG_LEVEL_INFO,
	LOG_LEVEL_WARN,
	LOG_LEVEL_ERROR,
	LOG_LEVEL_CRITICAL
} log_level_t;

/* Initialize logging system */
int logger_init(const char *log_file, int level, bool use_syslog);

/* Cleanup logging system */
void logger_cleanup(void);

/* Log functions */
void log_message(log_level_t level, const char *fmt, ...);
void log_attack(attack_type_t type, const ip_addr_t *src_ip,
                const char *details);
void log_packet_drop(const ip_addr_t *src_ip, const char *reason);

/* Convenience macros */
#define log_debug(fmt, ...) \
	log_message(LOG_LEVEL_DEBUG, "[DEBUG] " fmt, ##__VA_ARGS__)
#define log_info(fmt, ...) \
	log_message(LOG_LEVEL_INFO, "[INFO] " fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...) \
	log_message(LOG_LEVEL_WARN, "[WARN] " fmt, ##__VA_ARGS__)
#define log_error(fmt, ...) \
	log_message(LOG_LEVEL_ERROR, "[ERROR] " fmt, ##__VA_ARGS__)
#define log_critical(fmt, ...) \
	log_message(LOG_LEVEL_CRITICAL, "[CRITICAL] " fmt, ##__VA_ARGS__)

/* Log rotation */
int logger_rotate(void);

#endif /* DDOS_LOGGER_H */
