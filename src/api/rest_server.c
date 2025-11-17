/*
 * DDoS Protection System - REST API Server
 * Management API using libmicrohttpd
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <jansson.h>
#include "../../include/common.h"
#include "../../include/api.h"
#include "../../include/logger.h"

struct api_server {
	char *bind_addr;
	uint16_t port;
	char *auth_token;
	ddos_context_t *ctx;
	void *httpd;  /* MHD_Daemon */
	bool running;
	pthread_t thread;
};

static void *api_server_thread(void *arg)
{
	api_server_t *server = (api_server_t *)arg;

	log_info("API server thread started");

	/* In production, would run MHD_run() or event loop */
	while (server->running) {
		sleep(1);
	}

	log_info("API server thread stopped");

	return NULL;
}

api_server_t *api_server_init(const char *bind_addr, uint16_t port,
                               const char *auth_token, ddos_context_t *ctx)
{
	api_server_t *server;

	server = calloc(1, sizeof(*server));
	if (!server)
		return NULL;

	server->bind_addr = strdup(bind_addr ? bind_addr : "0.0.0.0");
	server->port = port;
	server->auth_token = auth_token ? strdup(auth_token) : NULL;
	server->ctx = ctx;
	server->running = false;

	log_info("API server initialized on %s:%u", server->bind_addr, port);

	return server;
}

int api_server_start(api_server_t *server)
{
	if (!server || server->running)
		return -1;

	/* In production, would start libmicrohttpd server:
	 * server->httpd = MHD_start_daemon(
	 *     MHD_USE_THREAD_PER_CONNECTION,
	 *     server->port,
	 *     NULL, NULL,
	 *     &api_handler, server,
	 *     MHD_OPTION_END);
	 */

	server->running = true;

	if (pthread_create(&server->thread, NULL, api_server_thread, server) != 0) {
		server->running = false;
		return -1;
	}

	log_info("API server started on port %u", server->port);

	return 0;
}

void api_server_stop(api_server_t *server)
{
	if (!server || !server->running)
		return;

	server->running = false;

	pthread_join(server->thread, NULL);

	/* MHD_stop_daemon(server->httpd); */

	log_info("API server stopped");
}

void api_server_cleanup(api_server_t *server)
{
	if (!server)
		return;

	if (server->running)
		api_server_stop(server);

	free(server->bind_addr);
	free(server->auth_token);
	free(server);
}
