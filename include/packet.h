#ifndef DDOS_PACKET_H
#define DDOS_PACKET_H

#include "common.h"
#include <pcap.h>

/* Packet capture */
typedef struct packet_capture packet_capture_t;

/* Initialize packet capture */
packet_capture_t *packet_capture_init(const char *interface, bool promiscuous,
                                       int snaplen);

/* Start packet capture (blocking) */
int packet_capture_start(packet_capture_t *pc,
                         void (*callback)(packet_t *pkt, void *user_data),
                         void *user_data);

/* Stop packet capture */
void packet_capture_stop(packet_capture_t *pc);

/* Cleanup */
void packet_capture_cleanup(packet_capture_t *pc);

/* Packet parsing */
int packet_parse(packet_t *pkt, const uint8_t *data, uint32_t len,
                 time_t timestamp);

/* Free packet */
void packet_free(packet_t *pkt);

/* Protocol parsers */
int parse_ethernet(packet_t *pkt);
int parse_ip(packet_t *pkt);
int parse_tcp(packet_t *pkt);
int parse_udp(packet_t *pkt);
int parse_icmp(packet_t *pkt);
int parse_http(packet_t *pkt);

/* TCP flags */
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

/* Packet filters */
bool packet_is_fragment(const packet_t *pkt);
bool packet_is_malformed(const packet_t *pkt);

#endif /* DDOS_PACKET_H */
