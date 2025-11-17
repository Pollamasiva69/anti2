#ifndef DDOS_PROTECTION_H
#define DDOS_PROTECTION_H

#include "common.h"

/* UDP protection */
verdict_t udp_protect_analyze(ddos_context_t *ctx, packet_t *pkt,
                               ip_stats_t *stats);
int udp_protect_init(ddos_context_t *ctx);
void udp_protect_cleanup(ddos_context_t *ctx);

/* TCP protection */
verdict_t tcp_protect_analyze(ddos_context_t *ctx, packet_t *pkt,
                               ip_stats_t *stats);
int tcp_protect_init(ddos_context_t *ctx);
void tcp_protect_cleanup(ddos_context_t *ctx);

/* ICMP protection */
verdict_t icmp_protect_analyze(ddos_context_t *ctx, packet_t *pkt,
                                ip_stats_t *stats);
int icmp_protect_init(ddos_context_t *ctx);
void icmp_protect_cleanup(ddos_context_t *ctx);

/* HTTP protection */
verdict_t http_protect_analyze(ddos_context_t *ctx, packet_t *pkt,
                                ip_stats_t *stats);
int http_protect_init(ddos_context_t *ctx);
void http_protect_cleanup(ddos_context_t *ctx);

/* Detection helpers */
bool is_dns_amplification(const packet_t *pkt);
bool is_ntp_amplification(const packet_t *pkt);
bool is_ssdp_reflection(const packet_t *pkt);
bool is_memcached_amplification(const packet_t *pkt);
bool is_slowloris_attack(ddos_context_t *ctx, const conn_entry_t *conn);
bool is_slow_post_attack(ddos_context_t *ctx, const packet_t *pkt);

#endif /* DDOS_PROTECTION_H */
