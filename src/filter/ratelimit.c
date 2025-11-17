/*
 * DDoS Protection System - Rate Limiting Engine
 * Token bucket and sliding window rate limiting
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "../../include/common.h"
#include "../../include/ratelimit.h"
#include "../../include/hashtable.h"
#include "../../include/logger.h"

#define RATE_LIMIT_BUCKETS 65536

/* Per-IP rate limit entry */
typedef struct {
	ip_addr_t ip;
	sliding_window_t *pps_window;
	sliding_window_t *bps_window;
	time_t last_update;
	uint64_t total_packets;
	uint64_t total_bytes;
} rate_limit_entry_t;

/* Rate limiter structure */
struct rate_limiter {
	rate_limit_entry_t **buckets;
	uint32_t max_pps;
	uint32_t max_bps;
	uint32_t window_size;
	pthread_rwlock_t *locks;
};

/* Sliding window implementation */
struct sliding_window {
	uint64_t *buckets;
	uint32_t size;
	uint32_t current_idx;
	time_t window_start;
	pthread_mutex_t lock;
};

sliding_window_t *sliding_window_create(uint32_t window_size)
{
	sliding_window_t *sw;

	sw = calloc(1, sizeof(*sw));
	if (!sw)
		return NULL;

	sw->size = window_size;
	sw->buckets = calloc(window_size, sizeof(uint64_t));
	if (!sw->buckets) {
		free(sw);
		return NULL;
	}

	sw->current_idx = 0;
	sw->window_start = time(NULL);

	pthread_mutex_init(&sw->lock, NULL);

	return sw;
}

void sliding_window_destroy(sliding_window_t *sw)
{
	if (!sw)
		return;

	free(sw->buckets);
	pthread_mutex_destroy(&sw->lock);
	free(sw);
}

void sliding_window_add(sliding_window_t *sw, uint64_t value, time_t now)
{
	if (!sw)
		return;

	pthread_mutex_lock(&sw->lock);

	/* Calculate time difference */
	time_t diff = now - sw->window_start;

	if (diff >= sw->size) {
		/* Window has completely moved, reset */
		memset(sw->buckets, 0, sw->size * sizeof(uint64_t));
		sw->current_idx = 0;
		sw->window_start = now;
		sw->buckets[0] = value;
	} else if (diff > 0) {
		/* Advance window */
		for (time_t i = 0; i < diff; i++) {
			sw->current_idx = (sw->current_idx + 1) % sw->size;
			sw->buckets[sw->current_idx] = 0;
		}
		sw->window_start = now;
		sw->buckets[sw->current_idx] += value;
	} else {
		/* Same second */
		sw->buckets[sw->current_idx] += value;
	}

	pthread_mutex_unlock(&sw->lock);
}

uint64_t sliding_window_sum(sliding_window_t *sw, time_t now)
{
	if (!sw)
		return 0;

	pthread_mutex_lock(&sw->lock);

	/* Update window first */
	time_t diff = now - sw->window_start;
	if (diff >= sw->size) {
		pthread_mutex_unlock(&sw->lock);
		return 0;
	}

	/* Sum all buckets */
	uint64_t sum = 0;
	for (uint32_t i = 0; i < sw->size; i++) {
		sum += sw->buckets[i];
	}

	pthread_mutex_unlock(&sw->lock);

	return sum;
}

rate_limiter_t *rate_limiter_create(uint32_t max_pps, uint32_t max_bps,
                                     uint32_t window_size)
{
	rate_limiter_t *rl;

	rl = calloc(1, sizeof(*rl));
	if (!rl)
		return NULL;

	rl->max_pps = max_pps;
	rl->max_bps = max_bps;
	rl->window_size = window_size;

	rl->buckets = calloc(RATE_LIMIT_BUCKETS, sizeof(rate_limit_entry_t *));
	if (!rl->buckets) {
		free(rl);
		return NULL;
	}

	rl->locks = calloc(RATE_LIMIT_BUCKETS, sizeof(pthread_rwlock_t));
	if (!rl->locks) {
		free(rl->buckets);
		free(rl);
		return NULL;
	}

	for (uint32_t i = 0; i < RATE_LIMIT_BUCKETS; i++) {
		pthread_rwlock_init(&rl->locks[i], NULL);
	}

	log_info("Rate limiter created (max_pps=%u, max_bps=%u, window=%us)",
	         max_pps, max_bps, window_size);

	return rl;
}

void rate_limiter_destroy(rate_limiter_t *rl)
{
	if (!rl)
		return;

	for (uint32_t i = 0; i < RATE_LIMIT_BUCKETS; i++) {
		rate_limit_entry_t *entry = rl->buckets[i];
		while (entry) {
			rate_limit_entry_t *next = (rate_limit_entry_t *)entry;
			sliding_window_destroy(entry->pps_window);
			sliding_window_destroy(entry->bps_window);
			free(entry);
			entry = next;
		}
		pthread_rwlock_destroy(&rl->locks[i]);
	}

	free(rl->buckets);
	free(rl->locks);
	free(rl);
}

static uint32_t ip_hash_simple(const ip_addr_t *ip)
{
	uint32_t hash = 0;

	if (ip->family == AF_INET) {
		hash = ntohl(ip->addr.v4.s_addr);
	} else {
		for (int i = 0; i < 4; i++) {
			hash ^= ((uint32_t *)&ip->addr.v6)[i];
		}
	}

	return hash % RATE_LIMIT_BUCKETS;
}

static rate_limit_entry_t *get_or_create_entry(rate_limiter_t *rl,
                                                const ip_addr_t *ip,
                                                uint32_t bucket_idx)
{
	/* Caller must hold write lock */

	rate_limit_entry_t *entry = rl->buckets[bucket_idx];

	/* Search for existing entry */
	while (entry) {
		if (ip_addr_compare(&entry->ip, ip) == 0) {
			return entry;
		}
		entry = (rate_limit_entry_t *)entry->pps_window;  /* Reusing ptr */
	}

	/* Create new entry */
	entry = calloc(1, sizeof(*entry));
	if (!entry)
		return NULL;

	memcpy(&entry->ip, ip, sizeof(*ip));
	entry->pps_window = sliding_window_create(rl->window_size);
	entry->bps_window = sliding_window_create(rl->window_size);
	entry->last_update = time(NULL);

	if (!entry->pps_window || !entry->bps_window) {
		sliding_window_destroy(entry->pps_window);
		sliding_window_destroy(entry->bps_window);
		free(entry);
		return NULL;
	}

	/* Insert at head */
	entry->pps_window = (sliding_window_t *)rl->buckets[bucket_idx];
	rl->buckets[bucket_idx] = entry;

	return entry;
}

bool rate_limiter_allow(rate_limiter_t *rl, const ip_addr_t *ip,
                        uint32_t packet_size)
{
	if (!rl || !ip)
		return true;

	uint32_t bucket_idx = ip_hash_simple(ip);
	time_t now = time(NULL);

	pthread_rwlock_wrlock(&rl->locks[bucket_idx]);

	rate_limit_entry_t *entry = get_or_create_entry(rl, ip, bucket_idx);
	if (!entry) {
		pthread_rwlock_unlock(&rl->locks[bucket_idx]);
		return true;  /* Fail open */
	}

	/* Update counters */
	sliding_window_add(entry->pps_window, 1, now);
	sliding_window_add(entry->bps_window, packet_size, now);

	entry->total_packets++;
	entry->total_bytes += packet_size;
	entry->last_update = now;

	/* Check rate limits */
	uint64_t current_pps = sliding_window_sum(entry->pps_window, now) /
	                       rl->window_size;
	uint64_t current_bps = sliding_window_sum(entry->bps_window, now) /
	                       rl->window_size;

	bool allowed = (current_pps <= rl->max_pps && current_bps <= rl->max_bps);

	pthread_rwlock_unlock(&rl->locks[bucket_idx]);

	return allowed;
}

void rate_limiter_update(rate_limiter_t *rl, time_t now)
{
	/* Periodic cleanup - not implemented in this version */
	(void)rl;
	(void)now;
}

uint64_t rate_limiter_get_pps(rate_limiter_t *rl, const ip_addr_t *ip)
{
	if (!rl || !ip)
		return 0;

	uint32_t bucket_idx = ip_hash_simple(ip);
	time_t now = time(NULL);

	pthread_rwlock_rdlock(&rl->locks[bucket_idx]);

	rate_limit_entry_t *entry = rl->buckets[bucket_idx];
	while (entry) {
		if (ip_addr_compare(&entry->ip, ip) == 0) {
			uint64_t pps = sliding_window_sum(entry->pps_window, now) /
			               rl->window_size;
			pthread_rwlock_unlock(&rl->locks[bucket_idx]);
			return pps;
		}
		entry = (rate_limit_entry_t *)entry->pps_window;
	}

	pthread_rwlock_unlock(&rl->locks[bucket_idx]);
	return 0;
}

uint64_t rate_limiter_get_bps(rate_limiter_t *rl, const ip_addr_t *ip)
{
	if (!rl || !ip)
		return 0;

	uint32_t bucket_idx = ip_hash_simple(ip);
	time_t now = time(NULL);

	pthread_rwlock_rdlock(&rl->locks[bucket_idx]);

	rate_limit_entry_t *entry = rl->buckets[bucket_idx];
	while (entry) {
		if (ip_addr_compare(&entry->ip, ip) == 0) {
			uint64_t bps = sliding_window_sum(entry->bps_window, now) /
			               rl->window_size;
			pthread_rwlock_unlock(&rl->locks[bucket_idx]);
			return bps;
		}
		entry = (rate_limit_entry_t *)entry->pps_window;
	}

	pthread_rwlock_unlock(&rl->locks[bucket_idx]);
	return 0;
}

void rate_limiter_reset(rate_limiter_t *rl, const ip_addr_t *ip)
{
	if (!rl || !ip)
		return;

	uint32_t bucket_idx = ip_hash_simple(ip);

	pthread_rwlock_wrlock(&rl->locks[bucket_idx]);

	rate_limit_entry_t *entry = rl->buckets[bucket_idx];
	rate_limit_entry_t *prev = NULL;

	while (entry) {
		if (ip_addr_compare(&entry->ip, ip) == 0) {
			if (prev) {
				prev->pps_window = entry->pps_window;
			} else {
				rl->buckets[bucket_idx] =
					(rate_limit_entry_t *)entry->pps_window;
			}

			sliding_window_destroy(entry->pps_window);
			sliding_window_destroy(entry->bps_window);
			free(entry);
			break;
		}

		prev = entry;
		entry = (rate_limit_entry_t *)entry->pps_window;
	}

	pthread_rwlock_unlock(&rl->locks[bucket_idx]);
}
