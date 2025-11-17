/*
 * DDoS Protection System - WebSocket Server
 * Real-time dashboard updates
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <jansson.h>
#include "../../include/common.h"
#include "../../include/websocket.h"
#include "../../include/logger.h"

struct websocket_server {
	uint16_t port;
	ddos_context_t *ctx;
	bool running;
	pthread_t thread;
};

static void *websocket_server_thread(void *arg)
{
	websocket_server_t *server = (websocket_server_t *)arg;

	log_info("WebSocket server thread started on port %u", server->port);

	/* In production, would run WebSocket event loop */
	while (server->running) {
		sleep(1);

		/* Broadcast stats every second */
		if (server->ctx && server->ctx->stats) {
			websocket_broadcast_stats(server, server->ctx->stats);
		}
	}

	log_info("WebSocket server thread stopped");

	return NULL;
}

websocket_server_t *websocket_server_init(uint16_t port, ddos_context_t *ctx)
{
	websocket_server_t *server;

	server = calloc(1, sizeof(*server));
	if (!server)
		return NULL;

	server->port = port;
	server->ctx = ctx;
	server->running = false;

	log_info("WebSocket server initialized on port %u", port);

	return server;
}

int websocket_server_start(websocket_server_t *server)
{
	if (!server || server->running)
		return -1;

	server->running = true;

	if (pthread_create(&server->thread, NULL,
	                   websocket_server_thread, server) != 0) {
		server->running = false;
		return -1;
	}

	log_info("WebSocket server started");

	return 0;
}

void websocket_server_stop(websocket_server_t *server)
{
	if (!server || !server->running)
		return;

	server->running = false;

	pthread_join(server->thread, NULL);

	log_info("WebSocket server stopped");
}

void websocket_server_cleanup(websocket_server_t *server)
{
	if (!server)
		return;

	if (server->running)
		websocket_server_stop(server);

	free(server);
}

int websocket_broadcast(websocket_server_t *server, const char *message)
{
	if (!server || !message)
		return -1;

	/* In production, would broadcast to all connected clients */
	log_debug("WebSocket broadcast: %s", message);

	return 0;
}

int websocket_broadcast_stats(websocket_server_t *server,
                               const global_stats_t *stats)
{
	if (!server || !stats)
		return -1;

	/* Create JSON stats message */
	json_t *root = json_object();

	json_object_set_new(root, "total_packets",
	                    json_integer(stats->total_packets));
	json_object_set_new(root, "total_bytes",
	                    json_integer(stats->total_bytes));
	json_object_set_new(root, "dropped_packets",
	                    json_integer(stats->dropped_packets));
	json_object_set_new(root, "current_connections",
	                    json_integer(stats->current_connections));

	char *json_str = json_dumps(root, JSON_COMPACT);

	websocket_broadcast(server, json_str);

	free(json_str);
	json_decref(root);

	return 0;
}

int websocket_broadcast_attack(websocket_server_t *server,
                                attack_type_t type,
                                const ip_addr_t *src_ip)
{
	if (!server || !src_ip)
		return -1;

	char ip_str[MAX_IP_STR_LEN];
	ip_addr_to_string(src_ip, ip_str, sizeof(ip_str));

	/* Create attack alert message */
	json_t *root = json_object();

	json_object_set_new(root, "type", json_string("attack"));
	json_object_set_new(root, "attack_type",
	                    json_string(attack_type_to_string(type)));
	json_object_set_new(root, "source_ip", json_string(ip_str));
	json_object_set_new(root, "timestamp", json_integer(time(NULL)));

	char *json_str = json_dumps(root, JSON_COMPACT);

	websocket_broadcast(server, json_str);

	free(json_str);
	json_decref(root);

	return 0;
}
