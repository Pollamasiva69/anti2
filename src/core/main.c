/*
 * DDoS Protection System - Main Entry Point
 * Enterprise-grade DDoS mitigation system
 * (c) 2025 - Multi-threaded packet processing engine
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <errno.h>

#include "../../include/common.h"
#include "../../include/config.h"
#include "../../include/logger.h"
#include "../../include/packet.h"
#include "../../include/hashtable.h"
#include "../../include/lru_cache.h"
#include "../../include/ipset.h"
#include "../../include/ratelimit.h"
#include "../../include/protection.h"
#include "../../include/analyzer.h"
#include "../../include/firewall.h"
#include "../../include/ebpf_loader.h"
#include "../../include/geoip.h"
#include "../../include/api.h"
#include "../../include/websocket.h"

/* Global context */
static ddos_context_t *g_ctx = NULL;
static volatile bool g_shutdown = false;

/* Statistics update thread */
static pthread_t g_stats_thread;
static pthread_t g_cleanup_thread;

/* Worker thread data */
typedef struct {
	int id;
	ddos_context_t *ctx;
	traffic_analyzer_t *analyzer;
	uint64_t packets_processed;
} worker_data_t;

/* Signal handler */
static void signal_handler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM) {
		log_info("Received signal %d, shutting down...", sig);
		g_shutdown = true;
		if (g_ctx) {
			g_ctx->running = false;
		}
	}
}

/* Setup signal handlers */
static int setup_signals(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if (sigaction(SIGINT, &sa, NULL) < 0) {
		perror("sigaction(SIGINT)");
		return -1;
	}

	if (sigaction(SIGTERM, &sa, NULL) < 0) {
		perror("sigaction(SIGTERM)");
		return -1;
	}

	/* Ignore SIGPIPE */
	signal(SIGPIPE, SIG_IGN);

	return 0;
}

/* Statistics update thread */
static void *stats_thread_func(void *arg)
{
	ddos_context_t *ctx = (ddos_context_t *)arg;

	log_info("Statistics thread started");

	while (ctx->running && !g_shutdown) {
		sleep(5);

		pthread_rwlock_rdlock(&ctx->stats->lock);

		log_info("Stats: packets=%lu, bytes=%lu, dropped=%lu, conns=%lu",
		         (unsigned long)ctx->stats->total_packets,
		         (unsigned long)ctx->stats->total_bytes,
		         (unsigned long)ctx->stats->dropped_packets,
		         (unsigned long)ctx->stats->current_connections);

		pthread_rwlock_unlock(&ctx->stats->lock);
	}

	log_info("Statistics thread stopped");

	return NULL;
}

/* Cleanup thread (expire old connections) */
static void *cleanup_thread_func(void *arg)
{
	ddos_context_t *ctx = (ddos_context_t *)arg;

	log_info("Cleanup thread started");

	while (ctx->running && !g_shutdown) {
		sleep(30);

		time_t now = time(NULL);

		/* Cleanup expired connections */
		lru_cache_t *cache = (lru_cache_t *)ctx->lru_cache;
		int cleaned = lru_cache_cleanup_expired(cache, now);

		if (cleaned > 0) {
			log_debug("Cleaned up %d expired connections", cleaned);
		}
	}

	log_info("Cleanup thread stopped");

	return NULL;
}

/* Packet processing callback */
static void packet_handler(packet_t *pkt, void *user_data)
{
	worker_data_t *worker = (worker_data_t *)user_data;
	ddos_context_t *ctx = worker->ctx;
	traffic_analyzer_t *analyzer = worker->analyzer;

	if (!pkt || !ctx || g_shutdown)
		return;

	worker->packets_processed++;

	/* Update global stats */
	pthread_rwlock_wrlock(&ctx->stats->lock);
	ctx->stats->total_packets++;
	ctx->stats->total_bytes += pkt->len;
	pthread_rwlock_unlock(&ctx->stats->lock);

	/* Analyze packet */
	verdict_t verdict = analyzer_process_packet(analyzer, pkt);

	/* Apply verdict */
	switch (verdict) {
	case VERDICT_DROP:
		pthread_rwlock_wrlock(&ctx->stats->lock);
		ctx->stats->dropped_packets++;
		pthread_rwlock_unlock(&ctx->stats->lock);

		/* Block at firewall if auto-blacklist enabled */
		if (ctx->config->auto_blacklist) {
			firewall_block_ip(&pkt->parsed.src_ip,
			                  ctx->config->blacklist_duration);
		}
		break;

	case VERDICT_RATE_LIMIT:
		pthread_rwlock_wrlock(&ctx->stats->lock);
		ctx->stats->rate_limited_packets++;
		pthread_rwlock_unlock(&ctx->stats->lock);
		break;

	case VERDICT_CHALLENGE:
		/* Would send challenge response */
		log_debug("Challenge requested for packet");
		break;

	case VERDICT_ACCEPT:
	default:
		/* Accept packet */
		break;
	}
}

/* Initialize global context */
static ddos_context_t *init_context(config_t *config)
{
	ddos_context_t *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		log_error("Failed to allocate context");
		return NULL;
	}

	ctx->config = config;
	ctx->running = true;

	/* Initialize global statistics */
	ctx->stats = calloc(1, sizeof(*ctx->stats));
	if (!ctx->stats) {
		free(ctx);
		return NULL;
	}

	pthread_rwlock_init(&ctx->stats->lock, NULL);
	ctx->stats->start_time = time(NULL);

	/* Create connection tracking table */
	ctx->conn_table = hashtable_create(HASH_TABLE_SIZE);
	if (!ctx->conn_table) {
		free(ctx->stats);
		free(ctx);
		return NULL;
	}

	/* Create LRU cache */
	ctx->lru_cache = lru_cache_create(LRU_CACHE_SIZE);
	if (!ctx->lru_cache) {
		hashtable_destroy(ctx->conn_table);
		free(ctx->stats);
		free(ctx);
		return NULL;
	}

	pthread_mutex_init(&ctx->global_lock, NULL);

	log_info("Global context initialized");

	return ctx;
}

/* Cleanup global context */
static void cleanup_context(ddos_context_t *ctx)
{
	if (!ctx)
		return;

	log_info("Cleaning up global context...");

	hashtable_destroy(ctx->conn_table);
	lru_cache_destroy(ctx->lru_cache);

	pthread_rwlock_destroy(&ctx->stats->lock);
	pthread_mutex_destroy(&ctx->global_lock);

	free(ctx->stats);
	free(ctx);
}

/* Drop privileges */
static int drop_privileges(const char *user, const char *group)
{
	/* In production, would use getpwnam/getgrnam and setuid/setgid */
	log_info("Would drop privileges to %s:%s", user, group);
	return 0;
}

/* Main function */
int main(int argc, char **argv)
{
	const char *config_file = "config/default.conf";
	int ret = EXIT_FAILURE;

	printf("DDoS Protection System v%s\n", DDOS_VERSION);
	printf("Enterprise-grade DDoS mitigation\n\n");

	/* Parse command line arguments */
	if (argc > 1) {
		config_file = argv[1];
	}

	/* Load configuration */
	config_t *config = config_load(config_file);
	if (!config) {
		fprintf(stderr, "Failed to load configuration from %s\n",
		        config_file);
		return EXIT_FAILURE;
	}

	/* Validate configuration */
	if (config_validate(config) != 0) {
		fprintf(stderr, "Invalid configuration\n");
		config_free(config);
		return EXIT_FAILURE;
	}

	/* Initialize logging */
	if (logger_init(config->log_file, config->log_level,
	                config->syslog_enabled) != 0) {
		fprintf(stderr, "Failed to initialize logging\n");
		config_free(config);
		return EXIT_FAILURE;
	}

	log_info("Starting DDoS Protection System v%s", DDOS_VERSION);
	log_info("Configuration: %s", config_file);

	/* Setup signal handlers */
	if (setup_signals() != 0) {
		log_error("Failed to setup signal handlers");
		goto cleanup;
	}

	/* Initialize global context */
	g_ctx = init_context(config);
	if (!g_ctx) {
		log_error("Failed to initialize context");
		goto cleanup;
	}

	/* Initialize firewall */
	if (firewall_init(FIREWALL_BACKEND_IPTABLES) != 0) {
		log_error("Failed to initialize firewall");
		goto cleanup;
	}

	/* Initialize protection modules */
	udp_protect_init(g_ctx);
	tcp_protect_init(g_ctx);
	icmp_protect_init(g_ctx);
	http_protect_init(g_ctx);

	/* Initialize traffic analyzer */
	traffic_analyzer_t *analyzer = analyzer_init(g_ctx);
	if (!analyzer) {
		log_error("Failed to initialize traffic analyzer");
		goto cleanup;
	}

	/* Initialize GeoIP (if enabled) */
	geoip_db_t *geoip = NULL;
	if (config->enable_geoip && config->geoip_db_path) {
		geoip = geoip_init(config->geoip_db_path);
		g_ctx->geoip_db = geoip;
	}

	/* Load XDP program (if enabled) */
	ebpf_program_t *xdp_prog = NULL;
	if (config->enable_xdp && config->xdp_program_path) {
		xdp_prog = ebpf_load_program(config->xdp_program_path,
		                              config->interface);
	}

	/* Start API server (if enabled) */
	api_server_t *api = NULL;
	if (config->enable_api) {
		api = api_server_init(config->api_bind_address,
		                      config->api_port,
		                      config->api_auth_token,
		                      g_ctx);
		if (api) {
			api_server_start(api);
		}
	}

	/* Start WebSocket server (if enabled) */
	websocket_server_t *websocket = NULL;
	if (config->enable_dashboard) {
		websocket = websocket_server_init(config->dashboard_port, g_ctx);
		if (websocket) {
			websocket_server_start(websocket);
		}
	}

	/* Start statistics thread */
	pthread_create(&g_stats_thread, NULL, stats_thread_func, g_ctx);

	/* Start cleanup thread */
	pthread_create(&g_cleanup_thread, NULL, cleanup_thread_func, g_ctx);

	/* Drop privileges if configured */
	if (config->drop_user && config->drop_group) {
		drop_privileges(config->drop_user, config->drop_group);
	}

	/* Initialize packet capture */
	packet_capture_t *pcap = packet_capture_init(
		config->interface,
		config->promiscuous_mode,
		config->snaplen);

	if (!pcap) {
		log_error("Failed to initialize packet capture");
		goto cleanup;
	}

	/* Setup worker data */
	worker_data_t worker = {
		.id = 0,
		.ctx = g_ctx,
		.analyzer = analyzer,
		.packets_processed = 0
	};

	log_info("Starting packet capture on %s...", config->interface);
	log_info("System ready - press Ctrl+C to stop");

	/* Main packet processing loop */
	packet_capture_start(pcap, packet_handler, &worker);

	log_info("Packet capture stopped");

	/* Wait for threads to finish */
	pthread_join(g_stats_thread, NULL);
	pthread_join(g_cleanup_thread, NULL);

	/* Cleanup */
	packet_capture_cleanup(pcap);

	if (websocket) {
		websocket_server_stop(websocket);
		websocket_server_cleanup(websocket);
	}

	if (api) {
		api_server_stop(api);
		api_server_cleanup(api);
	}

	if (xdp_prog) {
		ebpf_unload_program(xdp_prog);
	}

	if (geoip) {
		geoip_cleanup(geoip);
	}

	analyzer_cleanup(analyzer);

	udp_protect_cleanup(g_ctx);
	tcp_protect_cleanup(g_ctx);
	icmp_protect_cleanup(g_ctx);
	http_protect_cleanup(g_ctx);

	firewall_cleanup();

	ret = EXIT_SUCCESS;

cleanup:
	if (g_ctx) {
		cleanup_context(g_ctx);
		g_ctx = NULL;
	}

	if (config) {
		config_free(config);
	}

	logger_cleanup();

	log_info("DDoS Protection System stopped");

	return ret;
}
