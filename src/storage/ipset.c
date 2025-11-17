/*
 * DDoS Protection System - IP Set Management
 * Efficient IP whitelist/blacklist with CIDR support
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "../../include/common.h"
#include "../../include/ipset.h"
#include "../../include/logger.h"

/* IP set entry */
typedef struct ipset_entry {
	ip_addr_t ip;
	uint8_t prefix_len;  /* For CIDR */
	time_t expires;      /* 0 = never */
	struct ipset_entry *next;
} ipset_entry_t;

/* IP set structure */
struct ipset {
	ipset_entry_t **buckets;
	uint32_t bucket_count;
	uint32_t entry_count;
	uint32_t max_size;
	pthread_rwlock_t lock;
};

#define IPSET_BUCKETS 4096

ipset_t *ipset_create(uint32_t max_size)
{
	ipset_t *set;

	set = calloc(1, sizeof(*set));
	if (!set) {
		return NULL;
	}

	set->bucket_count = IPSET_BUCKETS;
	set->max_size = max_size;
	set->entry_count = 0;

	set->buckets = calloc(set->bucket_count, sizeof(ipset_entry_t *));
	if (!set->buckets) {
		free(set);
		return NULL;
	}

	pthread_rwlock_init(&set->lock, NULL);

	return set;
}

void ipset_destroy(ipset_t *set)
{
	if (!set)
		return;

	pthread_rwlock_wrlock(&set->lock);

	for (uint32_t i = 0; i < set->bucket_count; i++) {
		ipset_entry_t *entry = set->buckets[i];
		while (entry) {
			ipset_entry_t *next = entry->next;
			free(entry);
			entry = next;
		}
	}

	free(set->buckets);
	pthread_rwlock_unlock(&set->lock);
	pthread_rwlock_destroy(&set->lock);
	free(set);
}

static uint32_t ipset_hash(const ip_addr_t *ip)
{
	uint32_t hash = 0;

	if (ip->family == AF_INET) {
		hash = ntohl(ip->addr.v4.s_addr);
	} else {
		for (int i = 0; i < 4; i++) {
			hash ^= ((uint32_t *)&ip->addr.v6)[i];
		}
	}

	return hash % IPSET_BUCKETS;
}

int ipset_add(ipset_t *set, const ip_addr_t *ip)
{
	return ipset_add_expiring(set, ip, 0);
}

int ipset_add_expiring(ipset_t *set, const ip_addr_t *ip, time_t expires)
{
	if (!set || !ip)
		return -1;

	pthread_rwlock_wrlock(&set->lock);

	if (set->entry_count >= set->max_size) {
		pthread_rwlock_unlock(&set->lock);
		return -1;
	}

	uint32_t hash = ipset_hash(ip);

	/* Check if already exists */
	ipset_entry_t *entry = set->buckets[hash];
	while (entry) {
		if (ip_addr_compare(&entry->ip, ip) == 0 &&
		    entry->prefix_len == 32) {
			/* Update expiration */
			entry->expires = expires;
			pthread_rwlock_unlock(&set->lock);
			return 0;
		}
		entry = entry->next;
	}

	/* Create new entry */
	entry = calloc(1, sizeof(*entry));
	if (!entry) {
		pthread_rwlock_unlock(&set->lock);
		return -1;
	}

	memcpy(&entry->ip, ip, sizeof(*ip));
	entry->prefix_len = (ip->family == AF_INET) ? 32 : 128;
	entry->expires = expires;

	/* Insert at head */
	entry->next = set->buckets[hash];
	set->buckets[hash] = entry;
	set->entry_count++;

	pthread_rwlock_unlock(&set->lock);

	return 0;
}

int ipset_remove(ipset_t *set, const ip_addr_t *ip)
{
	if (!set || !ip)
		return -1;

	pthread_rwlock_wrlock(&set->lock);

	uint32_t hash = ipset_hash(ip);

	ipset_entry_t *entry = set->buckets[hash];
	ipset_entry_t *prev = NULL;

	while (entry) {
		if (ip_addr_compare(&entry->ip, ip) == 0) {
			if (prev) {
				prev->next = entry->next;
			} else {
				set->buckets[hash] = entry->next;
			}

			free(entry);
			set->entry_count--;

			pthread_rwlock_unlock(&set->lock);
			return 0;
		}

		prev = entry;
		entry = entry->next;
	}

	pthread_rwlock_unlock(&set->lock);
	return -1;
}

bool ipset_contains(ipset_t *set, const ip_addr_t *ip)
{
	if (!set || !ip)
		return false;

	pthread_rwlock_rdlock(&set->lock);

	uint32_t hash = ipset_hash(ip);
	time_t now = time(NULL);

	ipset_entry_t *entry = set->buckets[hash];
	while (entry) {
		/* Check expiration */
		if (entry->expires > 0 && now > entry->expires) {
			entry = entry->next;
			continue;
		}

		if (ip_addr_compare(&entry->ip, ip) == 0) {
			pthread_rwlock_unlock(&set->lock);
			return true;
		}

		entry = entry->next;
	}

	pthread_rwlock_unlock(&set->lock);
	return false;
}

static bool ip_in_cidr(const ip_addr_t *ip, const ip_addr_t *network,
                       uint8_t prefix_len)
{
	if (ip->family != network->family)
		return false;

	if (ip->family == AF_INET) {
		uint32_t mask = prefix_len ? htonl(~((1 << (32 - prefix_len)) - 1)) : 0;
		uint32_t ip_addr = ip->addr.v4.s_addr;
		uint32_t net_addr = network->addr.v4.s_addr;

		return (ip_addr & mask) == (net_addr & mask);
	} else {
		/* IPv6 CIDR matching */
		uint8_t *ip_bytes = (uint8_t *)&ip->addr.v6;
		uint8_t *net_bytes = (uint8_t *)&network->addr.v6;

		int full_bytes = prefix_len / 8;
		int remaining_bits = prefix_len % 8;

		if (memcmp(ip_bytes, net_bytes, full_bytes) != 0)
			return false;

		if (remaining_bits > 0) {
			uint8_t mask = ~((1 << (8 - remaining_bits)) - 1);
			if ((ip_bytes[full_bytes] & mask) !=
			    (net_bytes[full_bytes] & mask))
				return false;
		}

		return true;
	}
}

bool ipset_contains_cidr(ipset_t *set, const ip_addr_t *ip)
{
	if (!set || !ip)
		return false;

	pthread_rwlock_rdlock(&set->lock);

	time_t now = time(NULL);

	/* Check all buckets for CIDR matches */
	for (uint32_t i = 0; i < set->bucket_count; i++) {
		ipset_entry_t *entry = set->buckets[i];
		while (entry) {
			/* Check expiration */
			if (entry->expires > 0 && now > entry->expires) {
				entry = entry->next;
				continue;
			}

			if (ip_in_cidr(ip, &entry->ip, entry->prefix_len)) {
				pthread_rwlock_unlock(&set->lock);
				return true;
			}

			entry = entry->next;
		}
	}

	pthread_rwlock_unlock(&set->lock);
	return false;
}

int ipset_add_cidr(ipset_t *set, const char *cidr)
{
	if (!set || !cidr)
		return -1;

	char ip_str[MAX_IP_STR_LEN];
	uint32_t prefix_len;

	/* Parse CIDR notation */
	const char *slash = strchr(cidr, '/');
	if (!slash) {
		/* No prefix, assume /32 or /128 */
		strncpy(ip_str, cidr, sizeof(ip_str) - 1);
		prefix_len = 32;
	} else {
		size_t len = slash - cidr;
		if (len >= sizeof(ip_str))
			return -1;

		strncpy(ip_str, cidr, len);
		ip_str[len] = '\0';
		prefix_len = atoi(slash + 1);
	}

	ip_addr_t ip;
	if (string_to_ip_addr(ip_str, &ip) != 0)
		return -1;

	/* Validate prefix length */
	if (ip.family == AF_INET && prefix_len > 32)
		return -1;
	if (ip.family == AF_INET6 && prefix_len > 128)
		return -1;

	pthread_rwlock_wrlock(&set->lock);

	if (set->entry_count >= set->max_size) {
		pthread_rwlock_unlock(&set->lock);
		return -1;
	}

	uint32_t hash = ipset_hash(&ip);

	/* Create entry */
	ipset_entry_t *entry = calloc(1, sizeof(*entry));
	if (!entry) {
		pthread_rwlock_unlock(&set->lock);
		return -1;
	}

	memcpy(&entry->ip, &ip, sizeof(ip));
	entry->prefix_len = prefix_len;
	entry->expires = 0;

	/* Insert at head */
	entry->next = set->buckets[hash];
	set->buckets[hash] = entry;
	set->entry_count++;

	pthread_rwlock_unlock(&set->lock);

	return 0;
}

uint32_t ipset_size(ipset_t *set)
{
	if (!set)
		return 0;

	pthread_rwlock_rdlock(&set->lock);
	uint32_t size = set->entry_count;
	pthread_rwlock_unlock(&set->lock);

	return size;
}

void ipset_clear(ipset_t *set)
{
	if (!set)
		return;

	pthread_rwlock_wrlock(&set->lock);

	for (uint32_t i = 0; i < set->bucket_count; i++) {
		ipset_entry_t *entry = set->buckets[i];
		while (entry) {
			ipset_entry_t *next = entry->next;
			free(entry);
			entry = next;
		}
		set->buckets[i] = NULL;
	}

	set->entry_count = 0;

	pthread_rwlock_unlock(&set->lock);
}

int ipset_cleanup_expired(ipset_t *set, time_t now)
{
	if (!set)
		return -1;

	int cleaned = 0;

	pthread_rwlock_wrlock(&set->lock);

	for (uint32_t i = 0; i < set->bucket_count; i++) {
		ipset_entry_t *entry = set->buckets[i];
		ipset_entry_t *prev = NULL;

		while (entry) {
			if (entry->expires > 0 && now > entry->expires) {
				ipset_entry_t *next = entry->next;

				if (prev) {
					prev->next = next;
				} else {
					set->buckets[i] = next;
				}

				free(entry);
				set->entry_count--;
				cleaned++;

				entry = next;
			} else {
				prev = entry;
				entry = entry->next;
			}
		}
	}

	pthread_rwlock_unlock(&set->lock);

	return cleaned;
}

int ipset_load_from_file(ipset_t *set, const char *filename)
{
	FILE *fp = fopen(filename, "r");
	if (!fp)
		return -1;

	char line[256];
	int count = 0;

	while (fgets(line, sizeof(line), fp)) {
		/* Remove newline */
		line[strcspn(line, "\n")] = '\0';

		/* Skip comments and empty lines */
		if (line[0] == '#' || line[0] == '\0')
			continue;

		if (ipset_add_cidr(set, line) == 0) {
			count++;
		}
	}

	fclose(fp);

	log_info("Loaded %d IPs from %s", count, filename);

	return count;
}

int ipset_save_to_file(ipset_t *set, const char *filename)
{
	FILE *fp = fopen(filename, "w");
	if (!fp)
		return -1;

	int count = 0;

	pthread_rwlock_rdlock(&set->lock);

	for (uint32_t i = 0; i < set->bucket_count; i++) {
		ipset_entry_t *entry = set->buckets[i];
		while (entry) {
			char ip_str[MAX_IP_STR_LEN];
			ip_addr_to_string(&entry->ip, ip_str, sizeof(ip_str));

			fprintf(fp, "%s/%u\n", ip_str, entry->prefix_len);
			count++;

			entry = entry->next;
		}
	}

	pthread_rwlock_unlock(&set->lock);

	fclose(fp);

	log_info("Saved %d IPs to %s", count, filename);

	return count;
}
