/*
 * DDoS Protection System - HTTP/HTTPS Layer 7 Protection
 * HTTP floods, Slowloris, Slow POST, header anomalies, bot detection
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../../include/common.h"
#include "../../include/protection.h"
#include "../../include/logger.h"

struct http_protect_ctx {
	uint64_t total_http_requests;
	uint64_t dropped_requests;
	char **user_agent_blacklist;
	uint32_t blacklist_count;
	time_t last_update;
};

static struct http_protect_ctx *g_http_ctx = NULL;

int http_protect_init(ddos_context_t *ctx)
{
	g_http_ctx = calloc(1, sizeof(*g_http_ctx));
	if (!g_http_ctx) {
		log_error("Failed to initialize HTTP protection");
		return -1;
	}

	g_http_ctx->last_update = time(NULL);

	/* Load user-agent blacklist from config */
	if (ctx->config->user_agent_blacklist) {
		g_http_ctx->user_agent_blacklist =
			ctx->config->user_agent_blacklist;
		g_http_ctx->blacklist_count =
			ctx->config->user_agent_blacklist_count;
	}

	log_info("HTTP/HTTPS protection initialized");

	return 0;
}

void http_protect_cleanup(ddos_context_t *ctx)
{
	(void)ctx;

	if (g_http_ctx) {
		free(g_http_ctx);
		g_http_ctx = NULL;
	}
}

static bool is_user_agent_blacklisted(const char *user_agent)
{
	if (!user_agent || !g_http_ctx)
		return false;

	for (uint32_t i = 0; i < g_http_ctx->blacklist_count; i++) {
		if (strstr(user_agent, g_http_ctx->user_agent_blacklist[i])) {
			return true;
		}
	}

	/* Common bot patterns */
	const char *bot_patterns[] = {
		"bot", "crawler", "spider", "scraper",
		"python-requests", "curl", "wget"
	};

	for (size_t i = 0; i < sizeof(bot_patterns) / sizeof(bot_patterns[0]); i++) {
		if (strcasestr(user_agent, bot_patterns[i])) {
			return true;
		}
	}

	return false;
}

static bool is_http_header_anomaly(const packet_t *pkt)
{
	if (!pkt || !pkt->parsed.is_http)
		return false;

	const char *payload = (const char *)pkt->parsed.payload;
	uint32_t len = pkt->parsed.payload_len;

	/* Check for missing Host header (required in HTTP/1.1) */
	if (!strstr(payload, "Host:")) {
		return true;
	}

	/* Check for excessively long headers */
	const char *header_end = strstr(payload, "\r\n\r\n");
	if (header_end) {
		size_t header_len = header_end - payload;
		if (header_len > 8192) {  /* 8KB header limit */
			return true;
		}
	}

	/* Check for NULL bytes in headers */
	for (uint32_t i = 0; i < len && i < 2048; i++) {
		if (payload[i] == '\0') {
			return true;
		}
	}

	/* Check for invalid HTTP version */
	if (!strstr(payload, "HTTP/1.0") &&
	    !strstr(payload, "HTTP/1.1") &&
	    !strstr(payload, "HTTP/2")) {
		return true;
	}

	return false;
}

bool is_slow_post_attack(ddos_context_t *ctx, const packet_t *pkt)
{
	if (!pkt || !pkt->parsed.is_http)
		return false;

	/* POST request with Content-Length but minimal data */
	if (pkt->parsed.http_method &&
	    strcmp(pkt->parsed.http_method, "POST") == 0) {
		/* Large Content-Length but small payload */
		if (pkt->parsed.http_content_length > 10000 &&
		    pkt->parsed.payload_len < 500) {
			return true;
		}
	}

	return false;
}

verdict_t http_protect_analyze(ddos_context_t *ctx, packet_t *pkt,
                                ip_stats_t *stats)
{
	if (!ctx || !pkt || !stats)
		return VERDICT_ACCEPT;

	if (!pkt->parsed.is_http)
		return VERDICT_ACCEPT;

	if (!ctx->config->enable_http_protection)
		return VERDICT_ACCEPT;

	g_http_ctx->total_http_requests++;

	time_t now = time(NULL);

	/* HTTP flood detection */
	stats->http_rps++;

	if (now - stats->last_update >= 1) {
		if (stats->http_rps > ctx->config->http_rps_threshold) {
			attack_type_t attack = ATTACK_NONE;

			if (pkt->parsed.http_method &&
			    strcmp(pkt->parsed.http_method, "GET") == 0) {
				attack = ATTACK_HTTP_GET_FLOOD;
			} else if (pkt->parsed.http_method &&
			           strcmp(pkt->parsed.http_method, "POST") == 0) {
				attack = ATTACK_HTTP_POST_FLOOD;
			}

			if (attack != ATTACK_NONE) {
				stats->packets[attack]++;

				log_attack(attack, &pkt->parsed.src_ip,
				           "HTTP flood detected");

				pthread_rwlock_wrlock(&ctx->stats->lock);
				ctx->stats->attacks_detected[attack]++;
				pthread_rwlock_unlock(&ctx->stats->lock);

				g_http_ctx->dropped_requests++;

				if (ctx->config->enable_js_challenge) {
					/* Would send JavaScript challenge */
					return VERDICT_CHALLENGE;
				}

				return VERDICT_DROP;
			}
		}

		stats->http_rps = 0;
		stats->last_update = now;
	}

	/* User-Agent blacklist check */
	if (pkt->parsed.http_user_agent) {
		if (is_user_agent_blacklisted(pkt->parsed.http_user_agent)) {
			log_packet_drop(&pkt->parsed.src_ip,
			                "Blacklisted User-Agent");

			stats->packets[ATTACK_HTTP_GET_FLOOD]++;
			g_http_ctx->dropped_requests++;

			/* Lower reputation for bot-like behavior */
			stats->reputation_score = MAX(0, stats->reputation_score - 10);

			return VERDICT_DROP;
		}
	}

	/* Missing User-Agent (suspicious) */
	if (!pkt->parsed.http_user_agent) {
		log_debug("HTTP request without User-Agent from %s",
		          pkt->parsed.http_user_agent);

		stats->reputation_score = MAX(0, stats->reputation_score - 5);

		/* Still allow but flag as suspicious */
	}

	/* HTTP header anomaly detection */
	if (is_http_header_anomaly(pkt)) {
		attack_type_t attack = ATTACK_HTTP_HEADER_ANOMALY;
		stats->packets[attack]++;

		log_attack(attack, &pkt->parsed.src_ip,
		           "HTTP header anomaly detected");

		pthread_rwlock_wrlock(&ctx->stats->lock);
		ctx->stats->attacks_detected[attack]++;
		pthread_rwlock_unlock(&ctx->stats->lock);

		g_http_ctx->dropped_requests++;
		return VERDICT_DROP;
	}

	/* Slow POST attack detection */
	if (is_slow_post_attack(ctx, pkt)) {
		attack_type_t attack = ATTACK_SLOW_POST;
		stats->packets[attack]++;

		log_attack(attack, &pkt->parsed.src_ip,
		           "Slow POST attack detected");

		pthread_rwlock_wrlock(&ctx->stats->lock);
		ctx->stats->attacks_detected[attack]++;
		pthread_rwlock_unlock(&ctx->stats->lock);

		g_http_ctx->dropped_requests++;
		return VERDICT_DROP;
	}

	/* Reputation-based filtering */
	if (stats->reputation_score < 20) {
		log_info("Blocking low-reputation IP (score=%u)",
		         stats->reputation_score);

		if (ctx->config->enable_captcha) {
			/* Would present CAPTCHA */
			return VERDICT_CHALLENGE;
		}

		return VERDICT_DROP;
	}

	/* Increase reputation for legitimate requests */
	if (stats->reputation_score < 100) {
		stats->reputation_score = MIN(100, stats->reputation_score + 1);
	}

	return VERDICT_ACCEPT;
}
