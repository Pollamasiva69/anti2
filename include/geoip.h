#ifndef DDOS_GEOIP_H
#define DDOS_GEOIP_H

#include "common.h"

/* GeoIP database structure */
typedef struct geoip_db geoip_db_t;

/* Initialize GeoIP database */
geoip_db_t *geoip_init(const char *db_path);

/* Cleanup GeoIP database */
void geoip_cleanup(geoip_db_t *db);

/* Lookup country code for IP */
int geoip_lookup_country(geoip_db_t *db, const ip_addr_t *ip,
                         char *country_code, size_t len);

/* Lookup ASN for IP */
uint32_t geoip_lookup_asn(geoip_db_t *db, const ip_addr_t *ip);

/* Check if IP is from blocked country */
bool geoip_is_blocked_country(geoip_db_t *db, const ip_addr_t *ip,
                               const char **blocked_countries,
                               uint32_t count);

#endif /* DDOS_GEOIP_H */
