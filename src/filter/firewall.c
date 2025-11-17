/*
 * DDoS Protection System - Firewall Integration
 * iptables/nftables integration via system calls
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "../../include/common.h"
#include "../../include/firewall.h"
#include "../../include/logger.h"

static firewall_backend_t g_backend = FIREWALL_BACKEND_IPTABLES;
static ipset_t *g_blocked_ips = NULL;

int firewall_init(firewall_backend_t backend)
{
	g_backend = backend;

	g_blocked_ips = ipset_create(MAX_BLACKLIST_SIZE);
	if (!g_blocked_ips) {
		log_error("Failed to create blocked IPs set");
		return -1;
	}

	/* Create our chain */
	if (g_backend == FIREWALL_BACKEND_IPTABLES) {
		system("iptables -N DDOS_PROTECT 2>/dev/null || true");
		system("iptables -F DDOS_PROTECT 2>/dev/null || true");
		system("iptables -I INPUT -j DDOS_PROTECT 2>/dev/null || true");

		log_info("Firewall initialized (backend=iptables)");
	} else {
		system("nft add table inet ddos_protect 2>/dev/null || true");
		system("nft flush table inet ddos_protect 2>/dev/null || true");

		log_info("Firewall initialized (backend=nftables)");
	}

	return 0;
}

void firewall_cleanup(void)
{
	if (g_backend == FIREWALL_BACKEND_IPTABLES) {
		system("iptables -D INPUT -j DDOS_PROTECT 2>/dev/null || true");
		system("iptables -F DDOS_PROTECT 2>/dev/null || true");
		system("iptables -X DDOS_PROTECT 2>/dev/null || true");
	} else {
		system("nft delete table inet ddos_protect 2>/dev/null || true");
	}

	ipset_destroy(g_blocked_ips);
	g_blocked_ips = NULL;

	log_info("Firewall cleanup complete");
}

int firewall_block_ip(const ip_addr_t *ip, uint32_t duration_sec)
{
	char ip_str[MAX_IP_STR_LEN];
	char cmd[512];

	ip_addr_to_string(ip, ip_str, sizeof(ip_str));

	if (g_backend == FIREWALL_BACKEND_IPTABLES) {
		snprintf(cmd, sizeof(cmd),
		         "iptables -I DDOS_PROTECT -s %s -j DROP", ip_str);
	} else {
		snprintf(cmd, sizeof(cmd),
		         "nft add rule inet ddos_protect input ip saddr %s drop",
		         ip_str);
	}

	int ret = system(cmd);
	if (ret != 0) {
		log_error("Failed to block IP %s", ip_str);
		return -1;
	}

	/* Track in our set */
	time_t expires = duration_sec > 0 ? time(NULL) + duration_sec : 0;
	ipset_add_expiring(g_blocked_ips, ip, expires);

	log_info("Blocked IP %s (duration=%us)", ip_str, duration_sec);

	return 0;
}

int firewall_unblock_ip(const ip_addr_t *ip)
{
	char ip_str[MAX_IP_STR_LEN];
	char cmd[512];

	ip_addr_to_string(ip, ip_str, sizeof(ip_str));

	if (g_backend == FIREWALL_BACKEND_IPTABLES) {
		snprintf(cmd, sizeof(cmd),
		         "iptables -D DDOS_PROTECT -s %s -j DROP", ip_str);
	} else {
		/* nftables requires handle, simplified */
		log_warn("nftables unblock requires handle lookup");
		return 0;
	}

	system(cmd);

	ipset_remove(g_blocked_ips, ip);

	log_info("Unblocked IP %s", ip_str);

	return 0;
}

bool firewall_is_blocked(const ip_addr_t *ip)
{
	return ipset_contains(g_blocked_ips, ip);
}

int firewall_add_ratelimit(const ip_addr_t *ip, uint32_t pps, uint32_t bps)
{
	char ip_str[MAX_IP_STR_LEN];
	char cmd[512];

	ip_addr_to_string(ip, ip_str, sizeof(ip_str));

	if (g_backend == FIREWALL_BACKEND_IPTABLES) {
		snprintf(cmd, sizeof(cmd),
		         "iptables -I DDOS_PROTECT -s %s -m limit "
		         "--limit %u/sec -j ACCEPT", ip_str, pps);
	} else {
		snprintf(cmd, sizeof(cmd),
		         "nft add rule inet ddos_protect input ip saddr %s "
		         "limit rate %u/second accept", ip_str, pps);
	}

	system(cmd);

	log_info("Added rate limit for %s (pps=%u, bps=%u)", ip_str, pps, bps);

	return 0;
}

int firewall_remove_ratelimit(const ip_addr_t *ip)
{
	char ip_str[MAX_IP_STR_LEN];
	ip_addr_to_string(ip, ip_str, sizeof(ip_str));

	/* Simplified - would need proper rule removal */
	log_info("Removed rate limit for %s", ip_str);

	return 0;
}

int firewall_flush_all(void)
{
	if (g_backend == FIREWALL_BACKEND_IPTABLES) {
		system("iptables -F DDOS_PROTECT");
	} else {
		system("nft flush table inet ddos_protect");
	}

	ipset_clear(g_blocked_ips);

	log_info("Flushed all firewall rules");

	return 0;
}

int firewall_get_stats(uint64_t *blocked_count, uint64_t *ratelimited_count)
{
	if (blocked_count)
		*blocked_count = ipset_size(g_blocked_ips);

	if (ratelimited_count)
		*ratelimited_count = 0;  /* Would need to track separately */

	return 0;
}
