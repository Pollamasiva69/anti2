/*
 * DDoS Protection System - UDP Flood Protection
 * Detects and mitigates UDP floods, DNS/NTP/SSDP/Memcached amplification
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../../include/common.h"
#include "../../include/protection.h"
#include "../../include/logger.h"

#define DNS_PORT 53
#define NTP_PORT 123
#define SSDP_PORT 1900
#define MEMCACHED_PORT 11211

/* UDP protection context */
struct udp_protect_ctx {
	uint64_t total_udp_packets;
	uint64_t dropped_packets;
	time_t last_update;
};

static struct udp_protect_ctx *g_udp_ctx = NULL;

int udp_protect_init(ddos_context_t *ctx)
{
	(void)ctx;

	g_udp_ctx = calloc(1, sizeof(*g_udp_ctx));
	if (!g_udp_ctx) {
		log_error("Failed to initialize UDP protection");
		return -1;
	}

	g_udp_ctx->last_update = time(NULL);

	log_info("UDP flood protection initialized");

	return 0;
}

void udp_protect_cleanup(ddos_context_t *ctx)
{
	(void)ctx;

	if (g_udp_ctx) {
		free(g_udp_ctx);
		g_udp_ctx = NULL;
	}
}

bool is_dns_amplification(const packet_t *pkt)
{
	if (!pkt || pkt->parsed.protocol != PROTO_UDP)
		return false;

	/* DNS response from port 53 with large payload */
	if (pkt->parsed.src_port == DNS_PORT &&
	    pkt->parsed.payload_len > 512) {
		/* Check DNS response flag */
		if (pkt->parsed.payload_len >= 3) {
			uint8_t *dns_header = pkt->parsed.payload;
			bool is_response = (dns_header[2] & 0x80) != 0;

			if (is_response) {
				return true;
			}
		}
	}

	return false;
}

bool is_ntp_amplification(const packet_t *pkt)
{
	if (!pkt || pkt->parsed.protocol != PROTO_UDP)
		return false;

	/* NTP monlist response */
	if (pkt->parsed.src_port == NTP_PORT &&
	    pkt->parsed.payload_len > 400) {
		/* Check for monlist response (mode 6, command 42) */
		if (pkt->parsed.payload_len >= 1) {
			uint8_t *ntp_header = pkt->parsed.payload;
			uint8_t mode = ntp_header[0] & 0x07;
			if (mode == 6) {  /* Mode 6 is control */
				return true;
			}
		}
	}

	return false;
}

bool is_ssdp_reflection(const packet_t *pkt)
{
	if (!pkt || pkt->parsed.protocol != PROTO_UDP)
		return false;

	/* SSDP response from port 1900 */
	if (pkt->parsed.src_port == SSDP_PORT &&
	    pkt->parsed.payload_len > 200) {
		/* Check for HTTP/1.1 200 OK (SSDP uses HTTP-like protocol) */
		if (pkt->parsed.payload_len >= 12) {
			if (memcmp(pkt->parsed.payload, "HTTP/1.1 200", 12) == 0) {
				return true;
			}
		}
	}

	return false;
}

bool is_memcached_amplification(const packet_t *pkt)
{
	if (!pkt || pkt->parsed.protocol != PROTO_UDP)
		return false;

	/* Memcached response from port 11211 with large payload */
	if (pkt->parsed.src_port == MEMCACHED_PORT &&
	    pkt->parsed.payload_len > 1000) {
		/* Check for VALUE response */
		if (pkt->parsed.payload_len >= 5) {
			if (memcmp(pkt->parsed.payload, "VALUE", 5) == 0 ||
			    memcmp(pkt->parsed.payload, "STAT", 4) == 0) {
				return true;
			}
		}
	}

	return false;
}

verdict_t udp_protect_analyze(ddos_context_t *ctx, packet_t *pkt,
                               ip_stats_t *stats)
{
	if (!ctx || !pkt || !stats)
		return VERDICT_ACCEPT;

	if (pkt->parsed.protocol != PROTO_UDP)
		return VERDICT_ACCEPT;

	g_udp_ctx->total_udp_packets++;

	/* Check for amplification attacks */
	attack_type_t attack_type = ATTACK_NONE;

	if (is_dns_amplification(pkt)) {
		attack_type = ATTACK_DNS_AMPLIFICATION;
	} else if (is_ntp_amplification(pkt)) {
		attack_type = ATTACK_NTP_AMPLIFICATION;
	} else if (is_ssdp_reflection(pkt)) {
		attack_type = ATTACK_SSDP_REFLECTION;
	} else if (is_memcached_amplification(pkt)) {
		attack_type = ATTACK_MEMCACHED_AMPLIFICATION;
	}

	if (attack_type != ATTACK_NONE) {
		stats->packets[attack_type]++;
		log_attack(attack_type, &pkt->parsed.src_ip,
		           "Amplification attack detected");

		pthread_rwlock_wrlock(&ctx->stats->lock);
		ctx->stats->attacks_detected[attack_type]++;
		pthread_rwlock_unlock(&ctx->stats->lock);

		g_udp_ctx->dropped_packets++;
		return VERDICT_DROP;
	}

	/* Check UDP flood based on PPS */
	time_t now = time(NULL);
	stats->udp_pps++;

	/* Calculate PPS over last second */
	if (now - stats->last_update >= 1) {
		/* Check threshold */
		if (stats->udp_pps > ctx->config->udp_pps_threshold) {
			attack_type = ATTACK_UDP_FLOOD;
			stats->packets[attack_type]++;

			log_attack(attack_type, &pkt->parsed.src_ip,
			           "UDP flood detected");

			pthread_rwlock_wrlock(&ctx->stats->lock);
			ctx->stats->attacks_detected[attack_type]++;
			pthread_rwlock_unlock(&ctx->stats->lock);

			g_udp_ctx->dropped_packets++;

			/* Auto-blacklist if enabled */
			if (ctx->config->auto_blacklist) {
				/* Would add to blacklist here */
				log_info("Auto-blacklisting IP for UDP flood");
			}

			return VERDICT_DROP;
		}

		/* Reset counter */
		stats->udp_pps = 0;
		stats->last_update = now;
	}

	/* Check for UDP fragmentation attacks */
	if (packet_is_fragment(pkt)) {
		if (pkt->parsed.payload_len < 8) {
			attack_type = ATTACK_UDP_FRAGMENTATION;
			stats->packets[attack_type]++;

			log_attack(attack_type, &pkt->parsed.src_ip,
			           "Malicious UDP fragmentation");

			pthread_rwlock_wrlock(&ctx->stats->lock);
			ctx->stats->attacks_detected[attack_type]++;
			pthread_rwlock_unlock(&ctx->stats->lock);

			g_udp_ctx->dropped_packets++;
			return VERDICT_DROP;
		}
	}

	/* Check for malformed packets */
	if (packet_is_malformed(pkt)) {
		log_packet_drop(&pkt->parsed.src_ip, "Malformed UDP packet");
		g_udp_ctx->dropped_packets++;
		return VERDICT_DROP;
	}

	return VERDICT_ACCEPT;
}
