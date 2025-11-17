#ifndef DDOS_RATELIMIT_H
#define DDOS_RATELIMIT_H

#include "common.h"

/* Rate limiter structure */
typedef struct rate_limiter rate_limiter_t;

/* Create rate limiter */
rate_limiter_t *rate_limiter_create(uint32_t max_pps, uint32_t max_bps,
                                     uint32_t window_size);

/* Destroy rate limiter */
void rate_limiter_destroy(rate_limiter_t *rl);

/* Check if packet is allowed (returns true if allowed) */
bool rate_limiter_allow(rate_limiter_t *rl, const ip_addr_t *ip,
                        uint32_t packet_size);

/* Update rate limiter stats */
void rate_limiter_update(rate_limiter_t *rl, time_t now);

/* Get current PPS for IP */
uint64_t rate_limiter_get_pps(rate_limiter_t *rl, const ip_addr_t *ip);

/* Get current BPS for IP */
uint64_t rate_limiter_get_bps(rate_limiter_t *rl, const ip_addr_t *ip);

/* Reset rate limiter for IP */
void rate_limiter_reset(rate_limiter_t *rl, const ip_addr_t *ip);

/* Sliding window implementation */
sliding_window_t *sliding_window_create(uint32_t window_size);
void sliding_window_destroy(sliding_window_t *sw);
void sliding_window_add(sliding_window_t *sw, uint64_t value, time_t now);
uint64_t sliding_window_sum(sliding_window_t *sw, time_t now);

#endif /* DDOS_RATELIMIT_H */
