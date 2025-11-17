#ifndef DDOS_HASHTABLE_H
#define DDOS_HASHTABLE_H

#include "common.h"

/* Hash table structure */
typedef struct hashtable hashtable_t;

/* Create hash table */
hashtable_t *hashtable_create(uint32_t size);

/* Destroy hash table */
void hashtable_destroy(hashtable_t *ht);

/* Insert or update entry */
int hashtable_insert(hashtable_t *ht, const conn_tuple_t *key,
                     conn_entry_t *entry);

/* Lookup entry */
conn_entry_t *hashtable_lookup(hashtable_t *ht, const conn_tuple_t *key);

/* Remove entry */
int hashtable_remove(hashtable_t *ht, const conn_tuple_t *key);

/* Get number of entries */
uint64_t hashtable_size(hashtable_t *ht);

/* Clear all entries */
void hashtable_clear(hashtable_t *ht);

/* Iterate over entries (thread-safe) */
typedef int (*hashtable_iter_cb)(conn_entry_t *entry, void *user_data);
int hashtable_foreach(hashtable_t *ht, hashtable_iter_cb cb, void *user_data);

/* Hash function for connection tuple */
uint32_t conn_tuple_hash(const conn_tuple_t *tuple);

/* Connection tuple comparison */
int conn_tuple_compare(const conn_tuple_t *a, const conn_tuple_t *b);

#endif /* DDOS_HASHTABLE_H */
