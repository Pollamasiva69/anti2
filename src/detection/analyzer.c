/*
 * DDoS Protection System - Traffic Analyzer
 * ML-based pattern detection, behavioral analysis, entropy calculation
 */

#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include "../../include/common.h"
#include "../../include/analyzer.h"
#include "../../include/ipset.h"
#include "../../include/protection.h"
#include "../../include/logger.h"

#define IP_STATS_TABLE_SIZE 65536

struct traffic_analyzer {
	ddos_context_t *ctx;
	ip_stats_t **ip_table;
	pthread_rwlock_t *ip_locks;
	traffic_pattern_t baseline;
	ipset_t *blacklist;
	ipset_t *whitelist;
	time_t baseline_updated;
};

traffic_analyzer_t *analyzer_init(ddos_context_t *ctx)
{
	traffic_analyzer_t *analyzer;

	analyzer = calloc(1, sizeof(*analyzer));
	if (!analyzer)
		return NULL;

	analyzer->ctx = ctx;

	analyzer->ip_table = calloc(IP_STATS_TABLE_SIZE, sizeof(ip_stats_t *));
	if (!analyzer->ip_table) {
		free(analyzer);
		return NULL;
	}

	analyzer->ip_locks = calloc(IP_STATS_TABLE_SIZE, sizeof(pthread_rwlock_t));
	if (!analyzer->ip_locks) {
		free(analyzer->ip_table);
		free(analyzer);
		return NULL;
	}

	for (uint32_t i = 0; i < IP_STATS_TABLE_SIZE; i++) {
		pthread_rwlock_init(&analyzer->ip_locks[i], NULL);
	}

	analyzer->blacklist = ipset_create(MAX_BLACKLIST_SIZE);
	analyzer->whitelist = ipset_create(MAX_WHITELIST_SIZE);

	analyzer->baseline_updated = time(NULL);

	log_info("Traffic analyzer initialized");

	return analyzer;
}

void analyzer_cleanup(traffic_analyzer_t *analyzer)
{
	if (!analyzer)
		return;

	for (uint32_t i = 0; i < IP_STATS_TABLE_SIZE; i++) {
		ip_stats_t *stats = analyzer->ip_table[i];
		while (stats) {
			ip_stats_t *next = (ip_stats_t *)stats;
			free(stats);
			stats = next;
		}
		pthread_rwlock_destroy(&analyzer->ip_locks[i]);
	}

	free(analyzer->ip_table);
	free(analyzer->ip_locks);

	ipset_destroy(analyzer->blacklist);
	ipset_destroy(analyzer->whitelist);

	free(analyzer);
}

static uint32_t ip_stats_hash(const ip_addr_t *ip)
{
	uint32_t hash = 0;

	if (ip->family == AF_INET) {
		hash = ntohl(ip->addr.v4.s_addr);
	} else {
		for (int i = 0; i < 4; i++) {
			hash ^= ((uint32_t *)&ip->addr.v6)[i];
		}
	}

	return hash % IP_STATS_TABLE_SIZE;
}

ip_stats_t *analyzer_get_ip_stats(traffic_analyzer_t *analyzer,
                                   const ip_addr_t *ip)
{
	if (!analyzer || !ip)
		return NULL;

	uint32_t hash = ip_stats_hash(ip);

	pthread_rwlock_wrlock(&analyzer->ip_locks[hash]);

	/* Search for existing entry */
	ip_stats_t *stats = analyzer->ip_table[hash];
	while (stats) {
		if (ip_addr_compare(&stats->ip, ip) == 0) {
			pthread_rwlock_unlock(&analyzer->ip_locks[hash]);
			return stats;
		}
		stats = (ip_stats_t *)stats;  /* Next ptr reused */
	}

	/* Create new entry */
	stats = calloc(1, sizeof(*stats));
	if (!stats) {
		pthread_rwlock_unlock(&analyzer->ip_locks[hash]);
		return NULL;
	}

	memcpy(&stats->ip, ip, sizeof(*ip));
	stats->first_seen = time(NULL);
	stats->last_update = stats->first_seen;
	stats->reputation_score = 50;  /* Start at neutral */

	pthread_rwlock_init(&stats->lock, NULL);

	/* Insert at head */
	stats = (ip_stats_t *)analyzer->ip_table[hash];
	analyzer->ip_table[hash] = stats;

	pthread_rwlock_unlock(&analyzer->ip_locks[hash]);

	return stats;
}

void analyzer_update_reputation(traffic_analyzer_t *analyzer,
                                const ip_addr_t *ip, int delta)
{
	ip_stats_t *stats = analyzer_get_ip_stats(analyzer, ip);
	if (!stats)
		return;

	pthread_rwlock_wrlock(&stats->lock);

	stats->reputation_score += delta;
	if (stats->reputation_score > 100)
		stats->reputation_score = 100;
	if (stats->reputation_score < 0)
		stats->reputation_score = 0;

	/* Auto-blacklist very low reputation */
	if (stats->reputation_score < 10 && !stats->is_blacklisted) {
		stats->is_blacklisted = true;
		stats->blacklist_expires = time(NULL) +
		                           analyzer->ctx->config->blacklist_duration;

		ipset_add_expiring(analyzer->blacklist, ip,
		                   stats->blacklist_expires);

		log_info("Auto-blacklisted IP due to low reputation");
	}

	pthread_rwlock_unlock(&stats->lock);
}

double analyzer_calculate_entropy(traffic_analyzer_t *analyzer)
{
	double entropy = 0.0;
	uint64_t total_packets = 0;
	uint64_t counts[256] = {0};

	/* Simplified entropy calculation based on protocol distribution */
	for (uint32_t i = 0; i < IP_STATS_TABLE_SIZE; i++) {
		pthread_rwlock_rdlock(&analyzer->ip_locks[i]);

		ip_stats_t *stats = analyzer->ip_table[i];
		while (stats) {
			for (int j = 0; j < ATTACK_MAX; j++) {
				total_packets += stats->packets[j];
				counts[j % 256] += stats->packets[j];
			}
			stats = (ip_stats_t *)stats;
		}

		pthread_rwlock_unlock(&analyzer->ip_locks[i]);
	}

	if (total_packets == 0)
		return 0.0;

	/* Calculate Shannon entropy */
	for (int i = 0; i < 256; i++) {
		if (counts[i] > 0) {
			double p = (double)counts[i] / total_packets;
			entropy -= p * log2(p);
		}
	}

	return entropy;
}

int analyzer_update_baseline(traffic_analyzer_t *analyzer)
{
	if (!analyzer)
		return -1;

	/* Update baseline traffic pattern */
	analyzer->baseline.entropy = analyzer_calculate_entropy(analyzer);

	/* Calculate other baseline metrics */
	uint64_t total_packets = 0;
	uint64_t total_bytes = 0;
	uint32_t unique_ips = 0;

	for (uint32_t i = 0; i < IP_STATS_TABLE_SIZE; i++) {
		pthread_rwlock_rdlock(&analyzer->ip_locks[i]);

		ip_stats_t *stats = analyzer->ip_table[i];
		while (stats) {
			for (int j = 0; j < ATTACK_MAX; j++) {
				total_packets += stats->packets[j];
				total_bytes += stats->bytes[j];
			}
			unique_ips++;
			stats = (ip_stats_t *)stats;
		}

		pthread_rwlock_unlock(&analyzer->ip_locks[i]);
	}

	if (total_packets > 0) {
		analyzer->baseline.packet_size_avg = (double)total_bytes / total_packets;
	}

	analyzer->baseline.unique_src_ips = unique_ips;
	analyzer->baseline_updated = time(NULL);

	log_debug("Baseline updated: entropy=%.2f, avg_size=%.2f, ips=%u",
	          analyzer->baseline.entropy,
	          analyzer->baseline.packet_size_avg,
	          unique_ips);

	return 0;
}

bool analyzer_is_anomaly(traffic_analyzer_t *analyzer,
                         const traffic_pattern_t *pattern)
{
	if (!analyzer || !pattern)
		return false;

	/* Compare with baseline */
	double entropy_diff = fabs(pattern->entropy - analyzer->baseline.entropy);

	/* Entropy significantly different */
	if (entropy_diff > 2.0) {
		return true;
	}

	/* Packet size significantly different */
	if (pattern->packet_size_avg > 0 &&
	    analyzer->baseline.packet_size_avg > 0) {
		double size_ratio = pattern->packet_size_avg /
		                    analyzer->baseline.packet_size_avg;

		if (size_ratio > 5.0 || size_ratio < 0.2) {
			return true;
		}
	}

	return false;
}

/* Simple ML classification using thresholds (decision tree) */
attack_type_t analyzer_ml_classify(traffic_analyzer_t *analyzer,
                                    const packet_t *pkt)
{
	if (!analyzer || !pkt)
		return ATTACK_NONE;

	/* Simple rule-based classification */

	if (pkt->parsed.protocol == PROTO_UDP) {
		if (is_dns_amplification(pkt))
			return ATTACK_DNS_AMPLIFICATION;
		if (is_ntp_amplification(pkt))
			return ATTACK_NTP_AMPLIFICATION;
		if (is_ssdp_reflection(pkt))
			return ATTACK_SSDP_REFLECTION;
		if (is_memcached_amplification(pkt))
			return ATTACK_MEMCACHED_AMPLIFICATION;

		if (pkt->parsed.payload_len > 1400)
			return ATTACK_UDP_FLOOD;
	}

	if (pkt->parsed.protocol == PROTO_TCP) {
		if (pkt->parsed.tcp_flags == TCP_FLAG_SYN)
			return ATTACK_TCP_SYN_FLOOD;
		if (pkt->parsed.tcp_flags == TCP_FLAG_ACK)
			return ATTACK_TCP_ACK_FLOOD;
		if (pkt->parsed.tcp_flags & TCP_FLAG_RST)
			return ATTACK_TCP_RST_FLOOD;
	}

	if (pkt->parsed.protocol == PROTO_ICMP) {
		if (pkt->len > 1500)
			return ATTACK_PING_OF_DEATH;
		return ATTACK_ICMP_FLOOD;
	}

	if (pkt->parsed.is_http) {
		if (pkt->parsed.http_method) {
			if (strcmp(pkt->parsed.http_method, "GET") == 0)
				return ATTACK_HTTP_GET_FLOOD;
			if (strcmp(pkt->parsed.http_method, "POST") == 0)
				return ATTACK_HTTP_POST_FLOOD;
		}
	}

	return ATTACK_NONE;
}

int analyzer_ml_train(traffic_analyzer_t *analyzer)
{
	/* In a full implementation, this would train an ML model */
	/* For now, just update the baseline */
	return analyzer_update_baseline(analyzer);
}

verdict_t analyzer_process_packet(traffic_analyzer_t *analyzer, packet_t *pkt)
{
	if (!analyzer || !pkt)
		return VERDICT_ACCEPT;

	/* Get IP statistics */
	ip_stats_t *stats = analyzer_get_ip_stats(analyzer, &pkt->parsed.src_ip);
	if (!stats)
		return VERDICT_ACCEPT;

	/* Check whitelist */
	if (ipset_contains_cidr(analyzer->whitelist, &pkt->parsed.src_ip)) {
		stats->is_whitelisted = true;
		return VERDICT_ACCEPT;
	}

	/* Check blacklist */
	if (ipset_contains_cidr(analyzer->blacklist, &pkt->parsed.src_ip)) {
		stats->is_blacklisted = true;
		return VERDICT_DROP;
	}

	/* Run protocol-specific protection */
	verdict_t verdict = VERDICT_ACCEPT;

	switch (pkt->parsed.protocol) {
	case PROTO_UDP:
		verdict = udp_protect_analyze(analyzer->ctx, pkt, stats);
		break;

	case PROTO_TCP:
		verdict = tcp_protect_analyze(analyzer->ctx, pkt, stats);
		break;

	case PROTO_ICMP:
		verdict = icmp_protect_analyze(analyzer->ctx, pkt, stats);
		break;
	}

	/* HTTP layer check */
	if (verdict == VERDICT_ACCEPT && pkt->parsed.is_http) {
		verdict = http_protect_analyze(analyzer->ctx, pkt, stats);
	}

	/* Update reputation based on verdict */
	if (verdict == VERDICT_DROP) {
		analyzer_update_reputation(analyzer, &pkt->parsed.src_ip, -10);
	} else if (verdict == VERDICT_ACCEPT) {
		analyzer_update_reputation(analyzer, &pkt->parsed.src_ip, 1);
	}

	return verdict;
}
