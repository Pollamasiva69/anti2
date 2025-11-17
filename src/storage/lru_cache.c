/*
 * DDoS Protection System - LRU Cache
 * Thread-safe LRU cache for connection tracking
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "../../include/common.h"
#include "../../include/lru_cache.h"
#include "../../include/hashtable.h"
#include "../../include/logger.h"

/* LRU cache structure */
struct lru_cache {
	hashtable_t *table;
	conn_entry_t *head;  /* Most recently used */
	conn_entry_t *tail;  /* Least recently used */
	uint32_t max_size;
	uint32_t current_size;
	pthread_rwlock_t lock;
};

lru_cache_t *lru_cache_create(uint32_t max_size)
{
	lru_cache_t *cache;

	cache = calloc(1, sizeof(*cache));
	if (!cache) {
		log_error("Failed to allocate LRU cache");
		return NULL;
	}

	cache->max_size = max_size;
	cache->current_size = 0;
	cache->head = NULL;
	cache->tail = NULL;

	/* Create hash table for O(1) lookups */
	cache->table = hashtable_create(max_size);
	if (!cache->table) {
		free(cache);
		return NULL;
	}

	pthread_rwlock_init(&cache->lock, NULL);

	log_info("LRU cache created (max_size=%u)", max_size);

	return cache;
}

void lru_cache_destroy(lru_cache_t *cache)
{
	if (!cache)
		return;

	pthread_rwlock_wrlock(&cache->lock);

	/* Free all entries */
	conn_entry_t *entry = cache->head;
	while (entry) {
		conn_entry_t *next = entry->lru_next;
		free(entry);
		entry = next;
	}

	hashtable_destroy(cache->table);

	pthread_rwlock_unlock(&cache->lock);
	pthread_rwlock_destroy(&cache->lock);

	free(cache);
}

static void lru_move_to_head(lru_cache_t *cache, conn_entry_t *entry)
{
	/* Already at head */
	if (cache->head == entry)
		return;

	/* Remove from current position */
	if (entry->lru_prev) {
		entry->lru_prev->lru_next = entry->lru_next;
	}
	if (entry->lru_next) {
		entry->lru_next->lru_prev = entry->lru_prev;
	}

	/* Update tail if necessary */
	if (cache->tail == entry) {
		cache->tail = entry->lru_prev;
	}

	/* Insert at head */
	entry->lru_next = cache->head;
	entry->lru_prev = NULL;

	if (cache->head) {
		cache->head->lru_prev = entry;
	}

	cache->head = entry;

	/* Update tail if this is the first entry */
	if (!cache->tail) {
		cache->tail = entry;
	}
}

static conn_entry_t *lru_evict_lru(lru_cache_t *cache)
{
	conn_entry_t *entry = cache->tail;

	if (!entry)
		return NULL;

	/* Remove from list */
	if (entry->lru_prev) {
		entry->lru_prev->lru_next = NULL;
	}
	cache->tail = entry->lru_prev;

	if (cache->head == entry) {
		cache->head = NULL;
	}

	/* Remove from hash table */
	hashtable_remove(cache->table, &entry->tuple);

	cache->current_size--;

	return entry;
}

conn_entry_t *lru_cache_get(lru_cache_t *cache, const conn_tuple_t *key)
{
	if (!cache || !key)
		return NULL;

	pthread_rwlock_wrlock(&cache->lock);

	/* Lookup in hash table */
	conn_entry_t *entry = hashtable_lookup(cache->table, key);

	if (entry) {
		/* Move to head (most recently used) */
		lru_move_to_head(cache, entry);
		entry->last_seen = time(NULL);
		pthread_rwlock_unlock(&cache->lock);
		return entry;
	}

	/* Entry not found, create new one */
	entry = calloc(1, sizeof(*entry));
	if (!entry) {
		pthread_rwlock_unlock(&cache->lock);
		return NULL;
	}

	/* Initialize entry */
	memcpy(&entry->tuple, key, sizeof(*key));
	entry->first_seen = time(NULL);
	entry->last_seen = entry->first_seen;
	entry->packets = 0;
	entry->bytes = 0;
	entry->state = TCP_STATE_CLOSED;

	/* Evict LRU if cache is full */
	if (cache->current_size >= cache->max_size) {
		conn_entry_t *evicted = lru_evict_lru(cache);
		if (evicted) {
			free(evicted);
		}
	}

	/* Insert into hash table */
	hashtable_insert(cache->table, key, entry);

	/* Insert at head of LRU list */
	entry->lru_next = cache->head;
	entry->lru_prev = NULL;

	if (cache->head) {
		cache->head->lru_prev = entry;
	}
	cache->head = entry;

	if (!cache->tail) {
		cache->tail = entry;
	}

	cache->current_size++;

	pthread_rwlock_unlock(&cache->lock);

	return entry;
}

int lru_cache_update(lru_cache_t *cache, conn_entry_t *entry)
{
	if (!cache || !entry)
		return -1;

	pthread_rwlock_wrlock(&cache->lock);

	/* Move to head */
	lru_move_to_head(cache, entry);
	entry->last_seen = time(NULL);

	pthread_rwlock_unlock(&cache->lock);

	return 0;
}

int lru_cache_remove(lru_cache_t *cache, const conn_tuple_t *key)
{
	if (!cache || !key)
		return -1;

	pthread_rwlock_wrlock(&cache->lock);

	conn_entry_t *entry = hashtable_lookup(cache->table, key);
	if (!entry) {
		pthread_rwlock_unlock(&cache->lock);
		return -1;
	}

	/* Remove from LRU list */
	if (entry->lru_prev) {
		entry->lru_prev->lru_next = entry->lru_next;
	}
	if (entry->lru_next) {
		entry->lru_next->lru_prev = entry->lru_prev;
	}

	if (cache->head == entry) {
		cache->head = entry->lru_next;
	}
	if (cache->tail == entry) {
		cache->tail = entry->lru_prev;
	}

	/* Remove from hash table */
	hashtable_remove(cache->table, key);

	free(entry);
	cache->current_size--;

	pthread_rwlock_unlock(&cache->lock);

	return 0;
}

uint32_t lru_cache_size(lru_cache_t *cache)
{
	if (!cache)
		return 0;

	pthread_rwlock_rdlock(&cache->lock);
	uint32_t size = cache->current_size;
	pthread_rwlock_unlock(&cache->lock);

	return size;
}

int lru_cache_cleanup_expired(lru_cache_t *cache, time_t now)
{
	if (!cache)
		return -1;

	int cleaned = 0;

	pthread_rwlock_wrlock(&cache->lock);

	conn_entry_t *entry = cache->tail;

	while (entry) {
		conn_entry_t *prev = entry->lru_prev;

		/* Determine timeout based on protocol and state */
		time_t timeout;

		if (entry->tuple.protocol == PROTO_TCP) {
			switch (entry->state) {
			case TCP_STATE_SYN_SENT:
			case TCP_STATE_SYN_RECEIVED:
				timeout = TCP_SYN_TIMEOUT;
				break;
			case TCP_STATE_ESTABLISHED:
				timeout = TCP_ESTABLISHED_TIMEOUT;
				break;
			case TCP_STATE_FIN_WAIT:
			case TCP_STATE_CLOSE_WAIT:
				timeout = TCP_FIN_TIMEOUT;
				break;
			default:
				timeout = TCP_SYN_TIMEOUT;
			}
		} else if (entry->tuple.protocol == PROTO_UDP) {
			timeout = UDP_TIMEOUT;
		} else if (entry->tuple.protocol == PROTO_ICMP) {
			timeout = ICMP_TIMEOUT;
		} else {
			timeout = UDP_TIMEOUT;
		}

		/* Check if expired */
		if (now - entry->last_seen > timeout) {
			/* Remove from LRU list */
			if (entry->lru_prev) {
				entry->lru_prev->lru_next = entry->lru_next;
			}
			if (entry->lru_next) {
				entry->lru_next->lru_prev = entry->lru_prev;
			}

			if (cache->head == entry) {
				cache->head = entry->lru_next;
			}
			if (cache->tail == entry) {
				cache->tail = entry->lru_prev;
			}

			/* Remove from hash table */
			hashtable_remove(cache->table, &entry->tuple);

			free(entry);
			cache->current_size--;
			cleaned++;
		}

		entry = prev;
	}

	pthread_rwlock_unlock(&cache->lock);

	if (cleaned > 0) {
		log_debug("Cleaned %d expired connections", cleaned);
	}

	return cleaned;
}
