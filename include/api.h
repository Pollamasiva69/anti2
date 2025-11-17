#ifndef DDOS_API_H
#define DDOS_API_H

#include "common.h"

/* API server structure */
typedef struct api_server api_server_t;

/* Initialize API server */
api_server_t *api_server_init(const char *bind_addr, uint16_t port,
                               const char *auth_token, ddos_context_t *ctx);

/* Start API server (non-blocking) */
int api_server_start(api_server_t *server);

/* Stop API server */
void api_server_stop(api_server_t *server);

/* Cleanup API server */
void api_server_cleanup(api_server_t *server);

/* API endpoints */
/* GET /api/stats - Get global statistics */
/* GET /api/attacks - Get recent attacks */
/* GET /api/blacklist - Get blacklisted IPs */
/* POST /api/blacklist - Add IP to blacklist */
/* DELETE /api/blacklist/:ip - Remove IP from blacklist */
/* GET /api/whitelist - Get whitelisted IPs */
/* POST /api/whitelist - Add IP to whitelist */
/* DELETE /api/whitelist/:ip - Remove IP from whitelist */
/* GET /api/config - Get configuration */
/* PUT /api/config - Update configuration */
/* POST /api/config/reload - Reload configuration */
/* GET /api/connections - Get active connections */
/* GET /api/top-ips - Get top talkers */

#endif /* DDOS_API_H */
