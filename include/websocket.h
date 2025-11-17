#ifndef DDOS_WEBSOCKET_H
#define DDOS_WEBSOCKET_H

#include "common.h"

/* WebSocket server structure */
typedef struct websocket_server websocket_server_t;

/* Initialize WebSocket server */
websocket_server_t *websocket_server_init(uint16_t port, ddos_context_t *ctx);

/* Start WebSocket server (non-blocking) */
int websocket_server_start(websocket_server_t *server);

/* Stop WebSocket server */
void websocket_server_stop(websocket_server_t *server);

/* Cleanup WebSocket server */
void websocket_server_cleanup(websocket_server_t *server);

/* Broadcast message to all connected clients */
int websocket_broadcast(websocket_server_t *server, const char *message);

/* Broadcast statistics update */
int websocket_broadcast_stats(websocket_server_t *server,
                               const global_stats_t *stats);

/* Broadcast attack alert */
int websocket_broadcast_attack(websocket_server_t *server,
                                attack_type_t type,
                                const ip_addr_t *src_ip);

#endif /* DDOS_WEBSOCKET_H */
