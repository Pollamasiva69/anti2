/*
 * DDoS Protection System - ICMP Flood Protection
 * Ping flood, Smurf attack, Ping of Death, ICMP fragmentation protection
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netinet/ip_icmp.h>
#include "../../include/common.h"
#include "../../include/protection.h"
#include "../../include/logger.h"

struct icmp_protect_ctx {
	uint64_t total_icmp_packets;
	uint64_t dropped_packets;
	time_t last_update;
};

static struct icmp_protect_ctx *g_icmp_ctx = NULL;

int icmp_protect_init(ddos_context_t *ctx)
{
	(void)ctx;

	g_icmp_ctx = calloc(1, sizeof(*g_icmp_ctx));
	if (!g_icmp_ctx) {
		log_error("Failed to initialize ICMP protection");
		return -1;
	}

	g_icmp_ctx->last_update = time(NULL);
	log_info("ICMP flood protection initialized");

	return 0;
}

void icmp_protect_cleanup(ddos_context_t *ctx)
{
	(void)ctx;

	if (g_icmp_ctx) {
		free(g_icmp_ctx);
		g_icmp_ctx = NULL;
	}
}

verdict_t icmp_protect_analyze(ddos_context_t *ctx, packet_t *pkt,
                                ip_stats_t *stats)
{
	if (!ctx || !pkt || !stats)
		return VERDICT_ACCEPT;

	if (pkt->parsed.protocol != PROTO_ICMP)
		return VERDICT_ACCEPT;

	g_icmp_ctx->total_icmp_packets++;

	struct icmphdr *icmp = (struct icmphdr *)pkt->parsed.transport_header;
	time_t now = time(NULL);

	/* ICMP flood detection */
	stats->icmp_pps++;

	if (now - stats->last_update >= 1) {
		if (stats->icmp_pps > ctx->config->icmp_pps_threshold) {
			attack_type_t attack = ATTACK_ICMP_FLOOD;
			stats->packets[attack]++;

			log_attack(attack, &pkt->parsed.src_ip,
			           "ICMP flood detected");

			pthread_rwlock_wrlock(&ctx->stats->lock);
			ctx->stats->attacks_detected[attack]++;
			pthread_rwlock_unlock(&ctx->stats->lock);

			g_icmp_ctx->dropped_packets++;

			if (ctx->config->auto_blacklist) {
				log_info("Auto-blacklisting IP for ICMP flood");
			}

			return VERDICT_DROP;
		}

		stats->icmp_pps = 0;
		stats->last_update = now;
	}

	/* Ping of Death detection (oversized ICMP packets) */
	if (pkt->len > 65535 || pkt->parsed.payload_len > 65500) {
		attack_type_t attack = ATTACK_PING_OF_DEATH;
		stats->packets[attack]++;

		log_attack(attack, &pkt->parsed.src_ip,
		           "Ping of Death detected");

		pthread_rwlock_wrlock(&ctx->stats->lock);
		ctx->stats->attacks_detected[attack]++;
		pthread_rwlock_unlock(&ctx->stats->lock);

		g_icmp_ctx->dropped_packets++;
		return VERDICT_DROP;
	}

	/* ICMP fragmentation attack */
	if (packet_is_fragment(pkt)) {
		attack_type_t attack = ATTACK_ICMP_FRAGMENTATION;
		stats->packets[attack]++;

		log_attack(attack, &pkt->parsed.src_ip,
		           "ICMP fragmentation attack detected");

		pthread_rwlock_wrlock(&ctx->stats->lock);
		ctx->stats->attacks_detected[attack]++;
		pthread_rwlock_unlock(&ctx->stats->lock);

		g_icmp_ctx->dropped_packets++;
		return VERDICT_DROP;
	}

	/* Block ICMP redirect (security risk) */
	if (icmp->type == ICMP_REDIRECT) {
		log_packet_drop(&pkt->parsed.src_ip, "ICMP redirect blocked");
		g_icmp_ctx->dropped_packets++;
		return VERDICT_DROP;
	}

	/* Smurf attack detection (broadcast ping responses) */
	if (icmp->type == ICMP_ECHOREPLY) {
		/* Check if destination is broadcast */
		if (pkt->parsed.dst_ip.family == AF_INET) {
			uint32_t dst = ntohl(pkt->parsed.dst_ip.addr.v4.s_addr);
			/* Check for broadcast addresses */
			if ((dst & 0xFF) == 0xFF || dst == 0xFFFFFFFF) {
				attack_type_t attack = ATTACK_SMURF;
				stats->packets[attack]++;

				log_attack(attack, &pkt->parsed.src_ip,
				           "Smurf attack detected");

				pthread_rwlock_wrlock(&ctx->stats->lock);
				ctx->stats->attacks_detected[attack]++;
				pthread_rwlock_unlock(&ctx->stats->lock);

				g_icmp_ctx->dropped_packets++;
				return VERDICT_DROP;
			}
		}
	}

	/* Rate limit specific ICMP types */
	if (icmp->type != ICMP_ECHO && icmp->type != ICMP_ECHOREPLY) {
		/* Limit non-ping ICMP to lower threshold */
		if (stats->icmp_pps > ctx->config->icmp_pps_threshold / 10) {
			log_packet_drop(&pkt->parsed.src_ip,
			                "ICMP rate limit exceeded");
			g_icmp_ctx->dropped_packets++;
			return VERDICT_RATE_LIMIT;
		}
	}

	return VERDICT_ACCEPT;
}
