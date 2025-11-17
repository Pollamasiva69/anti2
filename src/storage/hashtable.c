/*
 * DDoS Protection System - Lock-free Hash Table
 * High-performance hash table for connection tracking
 */

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "../../include/common.h"
#include "../../include/hashtable.h"
#include "../../include/logger.h"

#define HASH_SEED 0x9747b28c

/* Hash table bucket */
struct hash_bucket {
	conn_entry_t *head;
	pthread_rwlock_t lock;
} __aligned(CACHE_LINE_SIZE);

/* Hash table structure */
struct hashtable {
	struct hash_bucket *buckets;
	uint32_t size;
	uint64_t entries;
	pthread_mutex_t global_lock;
};

/* MurmurHash3 32-bit implementation */
static inline uint32_t murmur3_32(const void *key, size_t len, uint32_t seed)
{
	const uint8_t *data = (const uint8_t *)key;
	const int nblocks = len / 4;
	uint32_t h1 = seed;
	const uint32_t c1 = 0xcc9e2d51;
	const uint32_t c2 = 0x1b873593;

	/* Body */
	const uint32_t *blocks = (const uint32_t *)(data + nblocks * 4);
	for (int i = -nblocks; i; i++) {
		uint32_t k1 = blocks[i];
		k1 *= c1;
		k1 = (k1 << 15) | (k1 >> 17);
		k1 *= c2;

		h1 ^= k1;
		h1 = (h1 << 13) | (h1 >> 19);
		h1 = h1 * 5 + 0xe6546b64;
	}

	/* Tail */
	const uint8_t *tail = (const uint8_t *)(data + nblocks * 4);
	uint32_t k1 = 0;
	switch (len & 3) {
	case 3:
		k1 ^= tail[2] << 16;
	case 2:
		k1 ^= tail[1] << 8;
	case 1:
		k1 ^= tail[0];
		k1 *= c1;
		k1 = (k1 << 15) | (k1 >> 17);
		k1 *= c2;
		h1 ^= k1;
	}

	/* Finalization */
	h1 ^= len;
	h1 ^= h1 >> 16;
	h1 *= 0x85ebca6b;
	h1 ^= h1 >> 13;
	h1 *= 0xc2b2ae35;
	h1 ^= h1 >> 16;

	return h1;
}

uint32_t conn_tuple_hash(const conn_tuple_t *tuple)
{
	/* Hash the connection tuple */
	uint32_t hash = HASH_SEED;

	/* Hash source IP */
	if (tuple->src_ip.family == AF_INET) {
		hash = murmur3_32(&tuple->src_ip.addr.v4,
		                  sizeof(struct in_addr), hash);
	} else {
		hash = murmur3_32(&tuple->src_ip.addr.v6,
		                  sizeof(struct in6_addr), hash);
	}

	/* Hash destination IP */
	if (tuple->dst_ip.family == AF_INET) {
		hash = murmur3_32(&tuple->dst_ip.addr.v4,
		                  sizeof(struct in_addr), hash);
	} else {
		hash = murmur3_32(&tuple->dst_ip.addr.v6,
		                  sizeof(struct in6_addr), hash);
	}

	/* Hash ports and protocol */
	hash = murmur3_32(&tuple->src_port, sizeof(tuple->src_port), hash);
	hash = murmur3_32(&tuple->dst_port, sizeof(tuple->dst_port), hash);
	hash = murmur3_32(&tuple->protocol, sizeof(tuple->protocol), hash);

	return hash;
}

int conn_tuple_compare(const conn_tuple_t *a, const conn_tuple_t *b)
{
	int cmp;

	if (a->protocol != b->protocol)
		return a->protocol - b->protocol;

	if (a->src_port != b->src_port)
		return a->src_port - b->src_port;

	if (a->dst_port != b->dst_port)
		return a->dst_port - b->dst_port;

	cmp = ip_addr_compare(&a->src_ip, &b->src_ip);
	if (cmp != 0)
		return cmp;

	return ip_addr_compare(&a->dst_ip, &b->dst_ip);
}

hashtable_t *hashtable_create(uint32_t size)
{
	hashtable_t *ht;

	ht = calloc(1, sizeof(*ht));
	if (!ht) {
		log_error("Failed to allocate hash table");
		return NULL;
	}

	ht->size = size;
	ht->entries = 0;

	ht->buckets = calloc(size, sizeof(struct hash_bucket));
	if (!ht->buckets) {
		log_error("Failed to allocate hash table buckets");
		free(ht);
		return NULL;
	}

	/* Initialize bucket locks */
	for (uint32_t i = 0; i < size; i++) {
		pthread_rwlock_init(&ht->buckets[i].lock, NULL);
	}

	pthread_mutex_init(&ht->global_lock, NULL);

	log_info("Hash table created (size=%u buckets)", size);

	return ht;
}

void hashtable_destroy(hashtable_t *ht)
{
	if (!ht)
		return;

	/* Free all entries */
	for (uint32_t i = 0; i < ht->size; i++) {
		conn_entry_t *entry = ht->buckets[i].head;
		while (entry) {
			conn_entry_t *next = entry->next;
			free(entry);
			entry = next;
		}
		pthread_rwlock_destroy(&ht->buckets[i].lock);
	}

	free(ht->buckets);
	pthread_mutex_destroy(&ht->global_lock);
	free(ht);
}

int hashtable_insert(hashtable_t *ht, const conn_tuple_t *key,
                     conn_entry_t *entry)
{
	if (!ht || !key || !entry)
		return -1;

	uint32_t hash = conn_tuple_hash(key);
	uint32_t idx = hash % ht->size;
	struct hash_bucket *bucket = &ht->buckets[idx];

	pthread_rwlock_wrlock(&bucket->lock);

	/* Check if entry already exists */
	conn_entry_t *curr = bucket->head;
	while (curr) {
		if (conn_tuple_compare(&curr->tuple, key) == 0) {
			/* Update existing entry */
			memcpy(curr, entry, sizeof(*entry));
			curr->next = curr->next;  /* Preserve list */
			pthread_rwlock_unlock(&bucket->lock);
			return 0;
		}
		curr = curr->next;
	}

	/* Insert new entry at head */
	entry->next = bucket->head;
	bucket->head = entry;

	pthread_rwlock_unlock(&bucket->lock);

	__sync_fetch_and_add(&ht->entries, 1);

	return 0;
}

conn_entry_t *hashtable_lookup(hashtable_t *ht, const conn_tuple_t *key)
{
	if (!ht || !key)
		return NULL;

	uint32_t hash = conn_tuple_hash(key);
	uint32_t idx = hash % ht->size;
	struct hash_bucket *bucket = &ht->buckets[idx];

	pthread_rwlock_rdlock(&bucket->lock);

	conn_entry_t *entry = bucket->head;
	while (entry) {
		if (conn_tuple_compare(&entry->tuple, key) == 0) {
			pthread_rwlock_unlock(&bucket->lock);
			return entry;
		}
		entry = entry->next;
	}

	pthread_rwlock_unlock(&bucket->lock);

	return NULL;
}

int hashtable_remove(hashtable_t *ht, const conn_tuple_t *key)
{
	if (!ht || !key)
		return -1;

	uint32_t hash = conn_tuple_hash(key);
	uint32_t idx = hash % ht->size;
	struct hash_bucket *bucket = &ht->buckets[idx];

	pthread_rwlock_wrlock(&bucket->lock);

	conn_entry_t *entry = bucket->head;
	conn_entry_t *prev = NULL;

	while (entry) {
		if (conn_tuple_compare(&entry->tuple, key) == 0) {
			if (prev) {
				prev->next = entry->next;
			} else {
				bucket->head = entry->next;
			}

			free(entry);
			pthread_rwlock_unlock(&bucket->lock);

			__sync_fetch_and_sub(&ht->entries, 1);
			return 0;
		}
		prev = entry;
		entry = entry->next;
	}

	pthread_rwlock_unlock(&bucket->lock);

	return -1;
}

uint64_t hashtable_size(hashtable_t *ht)
{
	if (!ht)
		return 0;
	return ht->entries;
}

void hashtable_clear(hashtable_t *ht)
{
	if (!ht)
		return;

	for (uint32_t i = 0; i < ht->size; i++) {
		struct hash_bucket *bucket = &ht->buckets[i];

		pthread_rwlock_wrlock(&bucket->lock);

		conn_entry_t *entry = bucket->head;
		while (entry) {
			conn_entry_t *next = entry->next;
			free(entry);
			entry = next;
		}
		bucket->head = NULL;

		pthread_rwlock_unlock(&bucket->lock);
	}

	ht->entries = 0;
}

int hashtable_foreach(hashtable_t *ht, hashtable_iter_cb cb, void *user_data)
{
	if (!ht || !cb)
		return -1;

	int count = 0;

	for (uint32_t i = 0; i < ht->size; i++) {
		struct hash_bucket *bucket = &ht->buckets[i];

		pthread_rwlock_rdlock(&bucket->lock);

		conn_entry_t *entry = bucket->head;
		while (entry) {
			int ret = cb(entry, user_data);
			if (ret != 0) {
				pthread_rwlock_unlock(&bucket->lock);
				return ret;
			}
			count++;
			entry = entry->next;
		}

		pthread_rwlock_unlock(&bucket->lock);
	}

	return count;
}
