/*
 * DDoS Protection System - Configuration Parser
 * JSON-based configuration with hot-reload support
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "../../include/common.h"
#include "../../include/config.h"
#include "../../include/logger.h"

static config_t *parse_config_json(json_t *root);

config_t *config_load(const char *filename)
{
	json_error_t error;
	json_t *root;

	root = json_load_file(filename, 0, &error);
	if (!root) {
		log_error("Failed to parse config file %s: %s (line %d)",
		          filename, error.text, error.line);
		return NULL;
	}

	config_t *config = parse_config_json(root);

	json_decref(root);

	if (config) {
		log_info("Configuration loaded from %s", filename);
	}

	return config;
}

static config_t *parse_config_json(json_t *root)
{
	config_t *config = calloc(1, sizeof(*config));
	if (!config)
		return NULL;

	/* Network settings */
	json_t *network = json_object_get(root, "network");
	if (network) {
		json_t *iface = json_object_get(network, "interface");
		if (iface && json_is_string(iface)) {
			config->interface = strdup(json_string_value(iface));
		}

		json_t *promisc = json_object_get(network, "promiscuous");
		config->promiscuous_mode = json_is_true(promisc);

		json_t *snaplen = json_object_get(network, "snaplen");
		config->snaplen = json_is_integer(snaplen) ?
		                  json_integer_value(snaplen) : 65535;
	}

	/* Worker threads */
	json_t *workers_obj = json_object_get(root, "workers");
	if (workers_obj && json_is_integer(workers_obj)) {
		config->num_workers = json_integer_value(workers_obj);
	} else {
		config->num_workers = 4;
	}

	json_t *cpu_affinity = json_object_get(root, "cpu_affinity");
	config->cpu_affinity = json_is_true(cpu_affinity);

	/* Thresholds */
	json_t *thresholds = json_object_get(root, "thresholds");
	if (thresholds) {
		json_t *udp_pps = json_object_get(thresholds, "udp_pps");
		config->udp_pps_threshold = json_is_integer(udp_pps) ?
		                            json_integer_value(udp_pps) :
		                            DEFAULT_UDP_PPS_THRESHOLD;

		json_t *tcp_syn_pps = json_object_get(thresholds, "tcp_syn_pps");
		config->tcp_syn_pps_threshold = json_is_integer(tcp_syn_pps) ?
		                                json_integer_value(tcp_syn_pps) :
		                                DEFAULT_TCP_SYN_PPS_THRESHOLD;

		json_t *icmp_pps = json_object_get(thresholds, "icmp_pps");
		config->icmp_pps_threshold = json_is_integer(icmp_pps) ?
		                             json_integer_value(icmp_pps) :
		                             DEFAULT_ICMP_PPS_THRESHOLD;

		json_t *http_rps = json_object_get(thresholds, "http_rps");
		config->http_rps_threshold = json_is_integer(http_rps) ?
		                             json_integer_value(http_rps) :
		                             DEFAULT_HTTP_RPS_THRESHOLD;
	}

	/* Rate limiting */
	json_t *ratelimit = json_object_get(root, "ratelimit");
	if (ratelimit) {
		config->enable_rate_limiting = json_is_true(
			json_object_get(ratelimit, "enabled"));

		json_t *pps = json_object_get(ratelimit, "pps");
		config->rate_limit_pps = json_is_integer(pps) ?
		                         json_integer_value(pps) : 1000;

		json_t *bps = json_object_get(ratelimit, "bps");
		config->rate_limit_bps = json_is_integer(bps) ?
		                         json_integer_value(bps) : 10000000;
	}

	/* Auto blacklist */
	json_t *blacklist_obj = json_object_get(root, "auto_blacklist");
	if (blacklist_obj) {
		config->auto_blacklist = json_is_true(
			json_object_get(blacklist_obj, "enabled"));

		json_t *duration = json_object_get(blacklist_obj, "duration");
		config->blacklist_duration = json_is_integer(duration) ?
		                             json_integer_value(duration) : 3600;
	}

	/* GeoIP */
	json_t *geoip = json_object_get(root, "geoip");
	if (geoip) {
		config->enable_geoip = json_is_true(
			json_object_get(geoip, "enabled"));

		json_t *db_path = json_object_get(geoip, "database");
		if (db_path && json_is_string(db_path)) {
			config->geoip_db_path = strdup(json_string_value(db_path));
		}
	}

	/* XDP */
	json_t *xdp = json_object_get(root, "xdp");
	if (xdp) {
		config->enable_xdp = json_is_true(
			json_object_get(xdp, "enabled"));

		json_t *prog_path = json_object_get(xdp, "program");
		if (prog_path && json_is_string(prog_path)) {
			config->xdp_program_path = strdup(json_string_value(prog_path));
		}
	}

	/* HTTP protection */
	json_t *http_protect = json_object_get(root, "http_protection");
	if (http_protect) {
		config->enable_http_protection = json_is_true(
			json_object_get(http_protect, "enabled"));
		config->enable_js_challenge = json_is_true(
			json_object_get(http_protect, "js_challenge"));
		config->enable_captcha = json_is_true(
			json_object_get(http_protect, "captcha"));
	}

	/* Logging */
	json_t *logging = json_object_get(root, "logging");
	if (logging) {
		json_t *log_file = json_object_get(logging, "file");
		if (log_file && json_is_string(log_file)) {
			config->log_file = strdup(json_string_value(log_file));
		}

		json_t *log_level = json_object_get(logging, "level");
		if (log_level && json_is_string(log_level)) {
			const char *level_str = json_string_value(log_level);
			if (strcmp(level_str, "debug") == 0)
				config->log_level = LOG_LEVEL_DEBUG;
			else if (strcmp(level_str, "info") == 0)
				config->log_level = LOG_LEVEL_INFO;
			else if (strcmp(level_str, "warn") == 0)
				config->log_level = LOG_LEVEL_WARN;
			else if (strcmp(level_str, "error") == 0)
				config->log_level = LOG_LEVEL_ERROR;
			else
				config->log_level = LOG_LEVEL_INFO;
		}

		config->syslog_enabled = json_is_true(
			json_object_get(logging, "syslog"));
	}

	/* API */
	json_t *api = json_object_get(root, "api");
	if (api) {
		config->enable_api = json_is_true(
			json_object_get(api, "enabled"));

		json_t *bind_addr = json_object_get(api, "bind_address");
		if (bind_addr && json_is_string(bind_addr)) {
			config->api_bind_address = strdup(json_string_value(bind_addr));
		}

		json_t *port = json_object_get(api, "port");
		config->api_port = json_is_integer(port) ?
		                   json_integer_value(port) : 8080;

		json_t *token = json_object_get(api, "auth_token");
		if (token && json_is_string(token)) {
			config->api_auth_token = strdup(json_string_value(token));
		}
	}

	/* Dashboard */
	json_t *dashboard = json_object_get(root, "dashboard");
	if (dashboard) {
		config->enable_dashboard = json_is_true(
			json_object_get(dashboard, "enabled"));

		json_t *port = json_object_get(dashboard, "port");
		config->dashboard_port = json_is_integer(port) ?
		                         json_integer_value(port) : 8081;
	}

	/* Security */
	json_t *security = json_object_get(root, "security");
	if (security) {
		config->enable_chroot = json_is_true(
			json_object_get(security, "chroot"));

		json_t *chroot_dir = json_object_get(security, "chroot_dir");
		if (chroot_dir && json_is_string(chroot_dir)) {
			config->chroot_dir = strdup(json_string_value(chroot_dir));
		}

		json_t *user = json_object_get(security, "drop_user");
		if (user && json_is_string(user)) {
			config->drop_user = strdup(json_string_value(user));
		}

		json_t *group = json_object_get(security, "drop_group");
		if (group && json_is_string(group)) {
			config->drop_group = strdup(json_string_value(group));
		}

		config->enable_seccomp = json_is_true(
			json_object_get(security, "seccomp"));
	}

	pthread_rwlock_init(&config->lock, NULL);

	return config;
}

void config_free(config_t *config)
{
	if (!config)
		return;

	free(config->interface);
	free(config->log_file);
	free(config->geoip_db_path);
	free(config->xdp_program_path);
	free(config->api_bind_address);
	free(config->api_auth_token);
	free(config->chroot_dir);
	free(config->drop_user);
	free(config->drop_group);

	pthread_rwlock_destroy(&config->lock);
	free(config);
}

int config_reload(config_t *config, const char *filename)
{
	config_t *new_config = config_load(filename);
	if (!new_config)
		return -1;

	pthread_rwlock_wrlock(&config->lock);

	/* Copy new configuration */
	/* Note: This is simplified, production would need careful handling */
	config_t temp = *config;
	*config = *new_config;
	*new_config = temp;

	pthread_rwlock_unlock(&config->lock);

	config_free(new_config);

	log_info("Configuration reloaded");

	return 0;
}

int config_validate(const config_t *config)
{
	if (!config)
		return -1;

	if (!config->interface) {
		log_error("No network interface specified");
		return -1;
	}

	if (config->num_workers == 0 || config->num_workers > MAX_WORKERS) {
		log_error("Invalid number of workers: %u", config->num_workers);
		return -1;
	}

	return 0;
}
