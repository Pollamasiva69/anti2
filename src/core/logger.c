/*
 * DDoS Protection System - Logger Module
 * High-performance rotatable logging with syslog integration
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <errno.h>
#include "../../include/common.h"
#include "../../include/logger.h"

#define MAX_LOG_LINE 4096
#define MAX_LOG_SIZE (100 * 1024 * 1024)  /* 100 MB */

struct logger {
	FILE *fp;
	char *log_file;
	int level;
	bool use_syslog;
	pthread_mutex_t lock;
	uint64_t bytes_written;
};

static struct logger g_logger = {
	.fp = NULL,
	.log_file = NULL,
	.level = LOG_LEVEL_INFO,
	.use_syslog = false,
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.bytes_written = 0
};

static const char *level_strings[] = {
	[LOG_LEVEL_DEBUG] = "DEBUG",
	[LOG_LEVEL_INFO] = "INFO",
	[LOG_LEVEL_WARN] = "WARN",
	[LOG_LEVEL_ERROR] = "ERROR",
	[LOG_LEVEL_CRITICAL] = "CRITICAL"
};

static int level_to_syslog[] = {
	[LOG_LEVEL_DEBUG] = LOG_DEBUG,
	[LOG_LEVEL_INFO] = LOG_INFO,
	[LOG_LEVEL_WARN] = LOG_WARNING,
	[LOG_LEVEL_ERROR] = LOG_ERR,
	[LOG_LEVEL_CRITICAL] = LOG_CRIT
};

int logger_init(const char *log_file, int level, bool use_syslog)
{
	pthread_mutex_lock(&g_logger.lock);

	g_logger.level = level;
	g_logger.use_syslog = use_syslog;

	if (log_file) {
		g_logger.log_file = strdup(log_file);
		if (!g_logger.log_file) {
			pthread_mutex_unlock(&g_logger.lock);
			return -1;
		}

		g_logger.fp = fopen(log_file, "a");
		if (!g_logger.fp) {
			fprintf(stderr, "Failed to open log file %s: %s\n",
			        log_file, strerror(errno));
			free(g_logger.log_file);
			g_logger.log_file = NULL;
			pthread_mutex_unlock(&g_logger.lock);
			return -1;
		}

		/* Set line buffering */
		setvbuf(g_logger.fp, NULL, _IOLBF, 0);
	}

	if (use_syslog) {
		openlog("ddos-protection", LOG_PID | LOG_CONS, LOG_DAEMON);
	}

	pthread_mutex_unlock(&g_logger.lock);

	log_info("Logger initialized (level=%s, syslog=%s)",
	         level_strings[level], use_syslog ? "yes" : "no");

	return 0;
}

void logger_cleanup(void)
{
	pthread_mutex_lock(&g_logger.lock);

	if (g_logger.fp) {
		fclose(g_logger.fp);
		g_logger.fp = NULL;
	}

	if (g_logger.log_file) {
		free(g_logger.log_file);
		g_logger.log_file = NULL;
	}

	if (g_logger.use_syslog) {
		closelog();
		g_logger.use_syslog = false;
	}

	pthread_mutex_unlock(&g_logger.lock);
}

void log_message(log_level_t level, const char *fmt, ...)
{
	if (level < g_logger.level)
		return;

	char message[MAX_LOG_LINE];
	va_list args;

	va_start(args, fmt);
	vsnprintf(message, sizeof(message), fmt, args);
	va_end(args);

	/* Get timestamp */
	time_t now = time(NULL);
	struct tm tm;
	localtime_r(&now, &tm);
	char timestamp[32];
	strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm);

	pthread_mutex_lock(&g_logger.lock);

	/* Write to file */
	if (g_logger.fp) {
		fprintf(g_logger.fp, "[%s] [%s] %s\n",
		        timestamp, level_strings[level], message);
		g_logger.bytes_written += strlen(message) + 64;

		/* Check for rotation */
		if (g_logger.bytes_written > MAX_LOG_SIZE) {
			logger_rotate();
		}
	}

	/* Write to syslog */
	if (g_logger.use_syslog) {
		syslog(level_to_syslog[level], "%s", message);
	}

	/* Also write to stderr for critical messages */
	if (level >= LOG_LEVEL_ERROR) {
		fprintf(stderr, "[%s] [%s] %s\n",
		        timestamp, level_strings[level], message);
	}

	pthread_mutex_unlock(&g_logger.lock);
}

void log_attack(attack_type_t type, const ip_addr_t *src_ip,
                const char *details)
{
	char ip_str[MAX_IP_STR_LEN];
	ip_addr_to_string(src_ip, ip_str, sizeof(ip_str));

	log_message(LOG_LEVEL_WARN, "ATTACK DETECTED: %s from %s - %s",
	            attack_type_to_string(type), ip_str,
	            details ? details : "");
}

void log_packet_drop(const ip_addr_t *src_ip, const char *reason)
{
	char ip_str[MAX_IP_STR_LEN];
	ip_addr_to_string(src_ip, ip_str, sizeof(ip_str));

	log_message(LOG_LEVEL_DEBUG, "Dropped packet from %s: %s",
	            ip_str, reason);
}

int logger_rotate(void)
{
	if (!g_logger.fp || !g_logger.log_file)
		return -1;

	/* Already locked by caller */

	/* Close current file */
	fclose(g_logger.fp);
	g_logger.fp = NULL;

	/* Rename current log file */
	char old_name[512];
	char new_name[512];
	time_t now = time(NULL);
	struct tm tm;
	localtime_r(&now, &tm);

	snprintf(old_name, sizeof(old_name), "%s", g_logger.log_file);
	snprintf(new_name, sizeof(new_name), "%s.%04d%02d%02d_%02d%02d%02d",
	         g_logger.log_file,
	         tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
	         tm.tm_hour, tm.tm_min, tm.tm_sec);

	if (rename(old_name, new_name) != 0) {
		fprintf(stderr, "Failed to rotate log: %s\n", strerror(errno));
	}

	/* Open new log file */
	g_logger.fp = fopen(g_logger.log_file, "a");
	if (!g_logger.fp) {
		fprintf(stderr, "Failed to reopen log file: %s\n",
		        strerror(errno));
		return -1;
	}

	setvbuf(g_logger.fp, NULL, _IOLBF, 0);
	g_logger.bytes_written = 0;

	log_info("Log file rotated");

	return 0;
}

/* IP address utilities implementation */
int ip_addr_compare(const ip_addr_t *a, const ip_addr_t *b)
{
	if (a->family != b->family)
		return a->family - b->family;

	if (a->family == AF_INET) {
		return memcmp(&a->addr.v4, &b->addr.v4, sizeof(struct in_addr));
	} else {
		return memcmp(&a->addr.v6, &b->addr.v6, sizeof(struct in6_addr));
	}
}

void ip_addr_to_string(const ip_addr_t *ip, char *buf, size_t len)
{
	if (ip->family == AF_INET) {
		inet_ntop(AF_INET, &ip->addr.v4, buf, len);
	} else {
		inet_ntop(AF_INET6, &ip->addr.v6, buf, len);
	}
}

int string_to_ip_addr(const char *str, ip_addr_t *ip)
{
	/* Try IPv4 first */
	if (inet_pton(AF_INET, str, &ip->addr.v4) == 1) {
		ip->family = AF_INET;
		return 0;
	}

	/* Try IPv6 */
	if (inet_pton(AF_INET6, str, &ip->addr.v6) == 1) {
		ip->family = AF_INET6;
		return 0;
	}

	return -1;
}
