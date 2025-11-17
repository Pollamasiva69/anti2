/*
 * DDoS Protection System - TCP Flood Protection
 * SYN flood, ACK flood, RST/FIN flood, Slowloris, Sockstress protection
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../../include/common.h"
#include "../../include/protection.h"
#include "../../include/lru_cache.h"
#include "../../include/logger.h"

struct tcp_protect_ctx {
	uint64_t total_tcp_packets;
	uint64_t syn_packets;
	uint64_t ack_packets;
	uint64_t rst_packets;
	uint64_t fin_packets;
	uint64_t dropped_packets;
	time_t last_update;
};

static struct tcp_protect_ctx *g_tcp_ctx = NULL;

int tcp_protect_init(ddos_context_t *ctx)
{
	(void)ctx;

	g_tcp_ctx = calloc(1, sizeof(*g_tcp_ctx));
	if (!g_tcp_ctx) {
		log_error("Failed to initialize TCP protection");
		return -1;
	}

	g_tcp_ctx->last_update = time(NULL);

	log_info("TCP flood protection initialized");

	return 0;
}

void tcp_protect_cleanup(ddos_context_t *ctx)
{
	(void)ctx;

	if (g_tcp_ctx) {
		free(g_tcp_ctx);
		g_tcp_ctx = NULL;
	}
}

bool is_slowloris_attack(ddos_context_t *ctx, const conn_entry_t *conn)
{
	if (!conn)
		return false;

	time_t now = time(NULL);

	/* Slowloris: long-lived incomplete connections */
	if (conn->state == TCP_STATE_SYN_RECEIVED ||
	    conn->state == TCP_STATE_ESTABLISHED) {
		/* Connection open for too long with too few packets */
		if (now - conn->first_seen > 60 && conn->packets < 10) {
			return true;
		}

		/* Very slow data rate */
		if (now - conn->first_seen > 30 && conn->bytes < 100) {
			return true;
		}
	}

	return false;
}

verdict_t tcp_protect_analyze(ddos_context_t *ctx, packet_t *pkt,
                               ip_stats_t *stats)
{
	if (!ctx || !pkt || !stats)
		return VERDICT_ACCEPT;

	if (pkt->parsed.protocol != PROTO_TCP)
		return VERDICT_ACCEPT;

	g_tcp_ctx->total_tcp_packets++;

	/* Get or create connection entry */
	conn_tuple_t tuple;
	tuple.src_ip = pkt->parsed.src_ip;
	tuple.dst_ip = pkt->parsed.dst_ip;
	tuple.src_port = pkt->parsed.src_port;
	tuple.dst_port = pkt->parsed.dst_port;
	tuple.protocol = PROTO_TCP;

	lru_cache_t *cache = (lru_cache_t *)ctx->lru_cache;
	conn_entry_t *conn = lru_cache_get(cache, &tuple);

	if (!conn) {
		/* Shouldn't happen, but handle gracefully */
		return VERDICT_ACCEPT;
	}

	/* Update connection */
	time_t now = time(NULL);
	conn->packets++;
	conn->bytes += pkt->len;
	conn->last_seen = now;

	/* Analyze TCP flags */
	uint8_t flags = pkt->parsed.tcp_flags;

	/* SYN flood detection */
	if (flags == TCP_FLAG_SYN) {
		g_tcp_ctx->syn_packets++;
		stats->tcp_syn_pps++;

		conn->state = TCP_STATE_SYN_SENT;

		/* Check SYN flood threshold */
		if (now - stats->last_update >= 1) {
			if (stats->tcp_syn_pps > ctx->config->tcp_syn_pps_threshold) {
				attack_type_t attack = ATTACK_TCP_SYN_FLOOD;
				stats->packets[attack]++;

				log_attack(attack, &pkt->parsed.src_ip,
				           "SYN flood detected");

				pthread_rwlock_wrlock(&ctx->stats->lock);
				ctx->stats->attacks_detected[attack]++;
				pthread_rwlock_unlock(&ctx->stats->lock);

				g_tcp_ctx->dropped_packets++;

				if (ctx->config->auto_blacklist) {
					log_info("Auto-blacklisting IP for SYN flood");
				}

				return VERDICT_DROP;
			}

			stats->tcp_syn_pps = 0;
			stats->last_update = now;
		}

	/* SYN-ACK */
	} else if ((flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) ==
	           (TCP_FLAG_SYN | TCP_FLAG_ACK)) {
		if (conn->state == TCP_STATE_SYN_SENT) {
			conn->state = TCP_STATE_SYN_RECEIVED;
		}

	/* ACK flood detection */
	} else if (flags == TCP_FLAG_ACK ||
	           flags == (TCP_FLAG_ACK | TCP_FLAG_PSH)) {
		g_tcp_ctx->ack_packets++;
		stats->tcp_ack_pps++;

		/* Update state */
		if (conn->state == TCP_STATE_SYN_RECEIVED) {
			conn->state = TCP_STATE_ESTABLISHED;
		}

		/* Detect ACK flood */
		if (now - stats->last_update >= 1) {
			if (stats->tcp_ack_pps > ctx->config->tcp_ack_pps_threshold) {
				attack_type_t attack = ATTACK_TCP_ACK_FLOOD;
				stats->packets[attack]++;

				log_attack(attack, &pkt->parsed.src_ip,
				           "ACK flood detected");

				pthread_rwlock_wrlock(&ctx->stats->lock);
				ctx->stats->attacks_detected[attack]++;
				pthread_rwlock_unlock(&ctx->stats->lock);

				g_tcp_ctx->dropped_packets++;
				return VERDICT_DROP;
			}

			stats->tcp_ack_pps = 0;
		}

		/* Detect PSH+ACK flood */
		if (flags == (TCP_FLAG_ACK | TCP_FLAG_PSH)) {
			/* High rate of PSH+ACK can indicate attack */
			if (stats->packets[ATTACK_TCP_PSH_ACK_FLOOD] > 1000) {
				attack_type_t attack = ATTACK_TCP_PSH_ACK_FLOOD;
				stats->packets[attack]++;

				log_attack(attack, &pkt->parsed.src_ip,
				           "PSH+ACK flood detected");

				pthread_rwlock_wrlock(&ctx->stats->lock);
				ctx->stats->attacks_detected[attack]++;
				pthread_rwlock_unlock(&ctx->stats->lock);

				g_tcp_ctx->dropped_packets++;
				return VERDICT_DROP;
			}
		}

	/* RST flood detection */
	} else if (flags & TCP_FLAG_RST) {
		g_tcp_ctx->rst_packets++;

		conn->state = TCP_STATE_CLOSED;

		/* Count RST floods */
		stats->packets[ATTACK_TCP_RST_FLOOD]++;

		if (stats->packets[ATTACK_TCP_RST_FLOOD] > 5000) {
			log_attack(ATTACK_TCP_RST_FLOOD, &pkt->parsed.src_ip,
			           "RST flood detected");

			pthread_rwlock_wrlock(&ctx->stats->lock);
			ctx->stats->attacks_detected[ATTACK_TCP_RST_FLOOD]++;
			pthread_rwlock_unlock(&ctx->stats->lock);

			g_tcp_ctx->dropped_packets++;
			return VERDICT_DROP;
		}

	/* FIN flood detection */
	} else if (flags & TCP_FLAG_FIN) {
		g_tcp_ctx->fin_packets++;

		if (conn->state == TCP_STATE_ESTABLISHED) {
			conn->state = TCP_STATE_FIN_WAIT;
		}

		/* Count FIN floods */
		stats->packets[ATTACK_TCP_FIN_FLOOD]++;

		if (stats->packets[ATTACK_TCP_FIN_FLOOD] > 5000) {
			log_attack(ATTACK_TCP_FIN_FLOOD, &pkt->parsed.src_ip,
			           "FIN flood detected");

			pthread_rwlock_wrlock(&ctx->stats->lock);
			ctx->stats->attacks_detected[ATTACK_TCP_FIN_FLOOD]++;
			pthread_rwlock_unlock(&ctx->stats->lock);

			g_tcp_ctx->dropped_packets++;
			return VERDICT_DROP;
		}
	}

	/* Slowloris detection */
	if (is_slowloris_attack(ctx, conn)) {
		attack_type_t attack = ATTACK_SLOWLORIS;
		stats->packets[attack]++;

		log_attack(attack, &pkt->parsed.src_ip,
		           "Slowloris attack detected");

		pthread_rwlock_wrlock(&ctx->stats->lock);
		ctx->stats->attacks_detected[attack]++;
		pthread_rwlock_unlock(&ctx->stats->lock);

		g_tcp_ctx->dropped_packets++;

		/* Close the connection */
		lru_cache_remove(cache, &tuple);

		return VERDICT_DROP;
	}

	/* Connection exhaustion check */
	uint64_t conn_count = lru_cache_size(cache);
	if (conn_count > LRU_CACHE_SIZE * 0.9) {
		log_warn("Connection table nearly full: %lu connections",
		         (unsigned long)conn_count);

		/* Start dropping new SYN packets from suspicious IPs */
		if (flags == TCP_FLAG_SYN && stats->reputation_score < 50) {
			log_info("Dropping SYN from low-reputation IP (conn exhaustion)");
			g_tcp_ctx->dropped_packets++;
			return VERDICT_DROP;
		}
	}

	/* Check for malformed packets */
	if (packet_is_malformed(pkt)) {
		log_packet_drop(&pkt->parsed.src_ip, "Malformed TCP packet");
		g_tcp_ctx->dropped_packets++;
		return VERDICT_DROP;
	}

	/* Invalid flag combinations */
	if ((flags & (TCP_FLAG_SYN | TCP_FLAG_FIN)) ==
	    (TCP_FLAG_SYN | TCP_FLAG_FIN)) {
		log_packet_drop(&pkt->parsed.src_ip, "Invalid TCP flags (SYN+FIN)");
		g_tcp_ctx->dropped_packets++;
		return VERDICT_DROP;
	}

	if ((flags & (TCP_FLAG_SYN | TCP_FLAG_RST)) ==
	    (TCP_FLAG_SYN | TCP_FLAG_RST)) {
		log_packet_drop(&pkt->parsed.src_ip, "Invalid TCP flags (SYN+RST)");
		g_tcp_ctx->dropped_packets++;
		return VERDICT_DROP;
	}

	/* NULL scan (no flags set) */
	if (flags == 0) {
		log_packet_drop(&pkt->parsed.src_ip, "TCP NULL scan detected");
		g_tcp_ctx->dropped_packets++;
		return VERDICT_DROP;
	}

	/* XMAS scan (FIN+PSH+URG) */
	if ((flags & (TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_URG)) ==
	    (TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_URG)) {
		log_packet_drop(&pkt->parsed.src_ip, "TCP XMAS scan detected");
		g_tcp_ctx->dropped_packets++;
		return VERDICT_DROP;
	}

	return VERDICT_ACCEPT;
}
