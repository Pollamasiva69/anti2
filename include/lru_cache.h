#ifndef DDOS_LRU_CACHE_H
#define DDOS_LRU_CACHE_H

#include "common.h"

/* LRU cache structure */
typedef struct lru_cache lru_cache_t;

/* Create LRU cache */
lru_cache_t *lru_cache_create(uint32_t max_size);

/* Destroy LRU cache */
void lru_cache_destroy(lru_cache_t *cache);

/* Get or create entry (marks as recently used) */
conn_entry_t *lru_cache_get(lru_cache_t *cache, const conn_tuple_t *key);

/* Update entry (marks as recently used) */
int lru_cache_update(lru_cache_t *cache, conn_entry_t *entry);

/* Remove entry */
int lru_cache_remove(lru_cache_t *cache, const conn_tuple_t *key);

/* Get cache size */
uint32_t lru_cache_size(lru_cache_t *cache);

/* Cleanup expired entries */
int lru_cache_cleanup_expired(lru_cache_t *cache, time_t now);

#endif /* DDOS_LRU_CACHE_H */
