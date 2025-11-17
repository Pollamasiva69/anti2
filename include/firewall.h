#ifndef DDOS_FIREWALL_H
#define DDOS_FIREWALL_H

#include "common.h"

/* Firewall backend type */
typedef enum {
	FIREWALL_BACKEND_IPTABLES,
	FIREWALL_BACKEND_NFTABLES
} firewall_backend_t;

/* Initialize firewall integration */
int firewall_init(firewall_backend_t backend);

/* Cleanup firewall */
void firewall_cleanup(void);

/* Block IP address */
int firewall_block_ip(const ip_addr_t *ip, uint32_t duration_sec);

/* Unblock IP address */
int firewall_unblock_ip(const ip_addr_t *ip);

/* Check if IP is blocked */
bool firewall_is_blocked(const ip_addr_t *ip);

/* Add rate limit rule for IP */
int firewall_add_ratelimit(const ip_addr_t *ip, uint32_t pps, uint32_t bps);

/* Remove rate limit rule for IP */
int firewall_remove_ratelimit(const ip_addr_t *ip);

/* Flush all rules */
int firewall_flush_all(void);

/* Get statistics */
int firewall_get_stats(uint64_t *blocked_count, uint64_t *ratelimited_count);

#endif /* DDOS_FIREWALL_H */
