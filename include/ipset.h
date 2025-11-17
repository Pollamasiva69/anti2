#ifndef DDOS_IPSET_H
#define DDOS_IPSET_H

#include "common.h"

/* IP set structure */
typedef struct ipset ipset_t;

/* Create IP set */
ipset_t *ipset_create(uint32_t max_size);

/* Destroy IP set */
void ipset_destroy(ipset_t *set);

/* Add IP to set */
int ipset_add(ipset_t *set, const ip_addr_t *ip);

/* Add IP with expiration */
int ipset_add_expiring(ipset_t *set, const ip_addr_t *ip, time_t expires);

/* Remove IP from set */
int ipset_remove(ipset_t *set, const ip_addr_t *ip);

/* Check if IP is in set */
bool ipset_contains(ipset_t *set, const ip_addr_t *ip);

/* Check if IP matches CIDR range */
bool ipset_contains_cidr(ipset_t *set, const ip_addr_t *ip);

/* Add CIDR range */
int ipset_add_cidr(ipset_t *set, const char *cidr);

/* Get set size */
uint32_t ipset_size(ipset_t *set);

/* Clear all entries */
void ipset_clear(ipset_t *set);

/* Remove expired entries */
int ipset_cleanup_expired(ipset_t *set, time_t now);

/* Load from file */
int ipset_load_from_file(ipset_t *set, const char *filename);

/* Save to file */
int ipset_save_to_file(ipset_t *set, const char *filename);

#endif /* DDOS_IPSET_H */
