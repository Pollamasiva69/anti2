/*
 * DDoS Protection System - Packet Capture
 * High-performance packet capture using libpcap and AF_PACKET
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include "../../include/common.h"
#include "../../include/packet.h"
#include "../../include/logger.h"

/* Packet capture structure */
struct packet_capture {
	pcap_t *handle;
	char *interface;
	bool promiscuous;
	int snaplen;
	bool running;
	pthread_mutex_t lock;
};

packet_capture_t *packet_capture_init(const char *interface, bool promiscuous,
                                       int snaplen)
{
	packet_capture_t *pc;
	char errbuf[PCAP_ERRBUF_SIZE];

	pc = calloc(1, sizeof(*pc));
	if (!pc) {
		log_error("Failed to allocate packet capture");
		return NULL;
	}

	pc->interface = strdup(interface);
	pc->promiscuous = promiscuous;
	pc->snaplen = snaplen;
	pc->running = false;

	/* Open packet capture handle */
	pc->handle = pcap_open_live(interface, snaplen,
	                             promiscuous ? 1 : 0,
	                             1000,  /* 1 second timeout */
	                             errbuf);
	if (!pc->handle) {
		log_error("Failed to open %s: %s", interface, errbuf);
		free(pc->interface);
		free(pc);
		return NULL;
	}

	/* Set non-blocking mode */
	if (pcap_setnonblock(pc->handle, 1, errbuf) == -1) {
		log_warn("Failed to set non-blocking mode: %s", errbuf);
	}

	/* Get data link type */
	int datalink = pcap_datalink(pc->handle);
	if (datalink != DLT_EN10MB) {
		log_error("Unsupported data link type: %d", datalink);
		pcap_close(pc->handle);
		free(pc->interface);
		free(pc);
		return NULL;
	}

	pthread_mutex_init(&pc->lock, NULL);

	log_info("Packet capture initialized on %s (snaplen=%d, promisc=%s)",
	         interface, snaplen, promiscuous ? "yes" : "no");

	return pc;
}

void packet_capture_cleanup(packet_capture_t *pc)
{
	if (!pc)
		return;

	pthread_mutex_lock(&pc->lock);

	if (pc->handle) {
		pcap_close(pc->handle);
		pc->handle = NULL;
	}

	free(pc->interface);

	pthread_mutex_unlock(&pc->lock);
	pthread_mutex_destroy(&pc->lock);

	free(pc);
}

void packet_capture_stop(packet_capture_t *pc)
{
	if (!pc)
		return;

	pthread_mutex_lock(&pc->lock);
	pc->running = false;
	if (pc->handle) {
		pcap_breakloop(pc->handle);
	}
	pthread_mutex_unlock(&pc->lock);

	log_info("Packet capture stopped");
}

/* Callback wrapper for pcap_loop */
struct capture_callback_data {
	void (*callback)(packet_t *pkt, void *user_data);
	void *user_data;
};

static void pcap_callback(u_char *user, const struct pcap_pkthdr *pkthdr,
                          const u_char *packet_data)
{
	struct capture_callback_data *cb_data =
		(struct capture_callback_data *)user;

	/* Allocate packet structure */
	packet_t *pkt = calloc(1, sizeof(*pkt));
	if (!pkt) {
		return;
	}

	/* Copy packet data */
	pkt->len = pkthdr->caplen;
	pkt->data = malloc(pkt->len);
	if (!pkt->data) {
		free(pkt);
		return;
	}

	memcpy(pkt->data, packet_data, pkt->len);
	pkt->timestamp = pkthdr->ts.tv_sec;

	/* Parse packet */
	if (packet_parse(pkt, pkt->data, pkt->len, pkt->timestamp) != 0) {
		packet_free(pkt);
		return;
	}

	/* Call user callback */
	cb_data->callback(pkt, cb_data->user_data);

	/* Free packet */
	packet_free(pkt);
}

int packet_capture_start(packet_capture_t *pc,
                         void (*callback)(packet_t *pkt, void *user_data),
                         void *user_data)
{
	if (!pc || !callback)
		return -1;

	pthread_mutex_lock(&pc->lock);
	pc->running = true;
	pthread_mutex_unlock(&pc->lock);

	log_info("Starting packet capture on %s", pc->interface);

	struct capture_callback_data cb_data = {
		.callback = callback,
		.user_data = user_data
	};

	/* Start capture loop */
	int ret = pcap_loop(pc->handle, -1, pcap_callback, (u_char *)&cb_data);

	if (ret == -1) {
		log_error("pcap_loop failed: %s", pcap_geterr(pc->handle));
		return -1;
	}

	return 0;
}

void packet_free(packet_t *pkt)
{
	if (!pkt)
		return;

	free(pkt->data);
	free(pkt->parsed.http_method);
	free(pkt->parsed.http_uri);
	free(pkt->parsed.http_user_agent);
	free(pkt);
}

bool packet_is_fragment(const packet_t *pkt)
{
	if (!pkt || !pkt->parsed.ip_header)
		return false;

	if (pkt->parsed.is_ipv4) {
		struct iphdr *ip = (struct iphdr *)pkt->parsed.ip_header;
		uint16_t frag_off = ntohs(ip->frag_off);
		return (frag_off & IP_OFFMASK) != 0 || (frag_off & IP_MF) != 0;
	}

	/* IPv6 fragmentation detection would go here */
	return false;
}

bool packet_is_malformed(const packet_t *pkt)
{
	if (!pkt)
		return true;

	/* Check minimum sizes */
	if (pkt->len < sizeof(struct ethhdr))
		return true;

	if (pkt->parsed.is_ipv4) {
		if (pkt->parsed.ip_len < sizeof(struct iphdr))
			return true;

		struct iphdr *ip = (struct iphdr *)pkt->parsed.ip_header;
		uint16_t ip_len = ntohs(ip->tot_len);

		if (ip_len < sizeof(struct iphdr))
			return true;

		if (ip_len > pkt->len - pkt->parsed.eth_len)
			return true;
	}

	/* Add more malformation checks as needed */

	return false;
}
