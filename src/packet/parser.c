/*
 * DDoS Protection System - Packet Parser
 * Multi-protocol packet parsing (Ethernet, IP, TCP, UDP, ICMP, HTTP)
 */

#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include "../../include/common.h"
#include "../../include/packet.h"
#include "../../include/logger.h"

int packet_parse(packet_t *pkt, const uint8_t *data, uint32_t len,
                 time_t timestamp)
{
	if (!pkt || !data || len == 0)
		return -1;

	pkt->data = (uint8_t *)data;
	pkt->len = len;
	pkt->timestamp = timestamp;

	/* Parse Ethernet */
	if (parse_ethernet(pkt) != 0)
		return -1;

	/* Parse IP */
	if (parse_ip(pkt) != 0)
		return -1;

	/* Parse transport layer */
	switch (pkt->parsed.protocol) {
	case PROTO_TCP:
		parse_tcp(pkt);
		/* Try HTTP parsing for TCP */
		if (pkt->parsed.dst_port == 80 || pkt->parsed.dst_port == 8080 ||
		    pkt->parsed.src_port == 80 || pkt->parsed.src_port == 8080) {
			parse_http(pkt);
		}
		break;

	case PROTO_UDP:
		parse_udp(pkt);
		break;

	case PROTO_ICMP:
		parse_icmp(pkt);
		break;

	default:
		/* Unknown protocol */
		break;
	}

	return 0;
}

int parse_ethernet(packet_t *pkt)
{
	if (pkt->len < sizeof(struct ethhdr))
		return -1;

	pkt->parsed.eth_header = pkt->data;
	pkt->parsed.eth_len = sizeof(struct ethhdr);

	return 0;
}

int parse_ip(packet_t *pkt)
{
	if (pkt->len < pkt->parsed.eth_len + sizeof(struct iphdr))
		return -1;

	pkt->parsed.ip_header = pkt->data + pkt->parsed.eth_len;

	/* Check IP version */
	uint8_t version = (pkt->parsed.ip_header[0] >> 4) & 0x0F;

	if (version == 4) {
		struct iphdr *ip = (struct iphdr *)pkt->parsed.ip_header;

		pkt->parsed.is_ipv4 = true;
		pkt->parsed.is_ipv6 = false;
		pkt->parsed.protocol = ip->protocol;
		pkt->parsed.ip_len = ip->ihl * 4;

		/* Extract source and destination IPs */
		pkt->parsed.src_ip.family = AF_INET;
		pkt->parsed.src_ip.addr.v4.s_addr = ip->saddr;

		pkt->parsed.dst_ip.family = AF_INET;
		pkt->parsed.dst_ip.addr.v4.s_addr = ip->daddr;

		pkt->parsed.transport_header = pkt->parsed.ip_header +
		                                pkt->parsed.ip_len;
		pkt->parsed.transport_len = ntohs(ip->tot_len) -
		                            pkt->parsed.ip_len;

	} else if (version == 6) {
		struct ip6_hdr *ip6 = (struct ip6_hdr *)pkt->parsed.ip_header;

		pkt->parsed.is_ipv4 = false;
		pkt->parsed.is_ipv6 = true;
		pkt->parsed.protocol = ip6->ip6_nxt;
		pkt->parsed.ip_len = sizeof(struct ip6_hdr);

		/* Extract source and destination IPs */
		pkt->parsed.src_ip.family = AF_INET6;
		memcpy(&pkt->parsed.src_ip.addr.v6, &ip6->ip6_src,
		       sizeof(struct in6_addr));

		pkt->parsed.dst_ip.family = AF_INET6;
		memcpy(&pkt->parsed.dst_ip.addr.v6, &ip6->ip6_dst,
		       sizeof(struct in6_addr));

		pkt->parsed.transport_header = pkt->parsed.ip_header +
		                                pkt->parsed.ip_len;
		pkt->parsed.transport_len = ntohs(ip6->ip6_plen);

	} else {
		return -1;
	}

	return 0;
}

int parse_tcp(packet_t *pkt)
{
	if (pkt->parsed.transport_len < sizeof(struct tcphdr))
		return -1;

	struct tcphdr *tcp = (struct tcphdr *)pkt->parsed.transport_header;

	pkt->parsed.src_port = ntohs(tcp->source);
	pkt->parsed.dst_port = ntohs(tcp->dest);
	pkt->parsed.tcp_seq = ntohl(tcp->seq);
	pkt->parsed.tcp_ack = ntohl(tcp->ack_seq);

	/* Extract TCP flags */
	pkt->parsed.tcp_flags = 0;
	if (tcp->fin)
		pkt->parsed.tcp_flags |= TCP_FLAG_FIN;
	if (tcp->syn)
		pkt->parsed.tcp_flags |= TCP_FLAG_SYN;
	if (tcp->rst)
		pkt->parsed.tcp_flags |= TCP_FLAG_RST;
	if (tcp->psh)
		pkt->parsed.tcp_flags |= TCP_FLAG_PSH;
	if (tcp->ack)
		pkt->parsed.tcp_flags |= TCP_FLAG_ACK;
	if (tcp->urg)
		pkt->parsed.tcp_flags |= TCP_FLAG_URG;

	/* Calculate payload offset */
	uint32_t tcp_header_len = tcp->doff * 4;
	if (tcp_header_len > pkt->parsed.transport_len)
		return -1;

	pkt->parsed.payload = pkt->parsed.transport_header + tcp_header_len;
	pkt->parsed.payload_len = pkt->parsed.transport_len - tcp_header_len;

	return 0;
}

int parse_udp(packet_t *pkt)
{
	if (pkt->parsed.transport_len < sizeof(struct udphdr))
		return -1;

	struct udphdr *udp = (struct udphdr *)pkt->parsed.transport_header;

	pkt->parsed.src_port = ntohs(udp->source);
	pkt->parsed.dst_port = ntohs(udp->dest);

	/* Calculate payload */
	pkt->parsed.payload = pkt->parsed.transport_header +
	                      sizeof(struct udphdr);
	pkt->parsed.payload_len = pkt->parsed.transport_len -
	                          sizeof(struct udphdr);

	return 0;
}

int parse_icmp(packet_t *pkt)
{
	if (pkt->parsed.transport_len < sizeof(struct icmphdr))
		return -1;

	struct icmphdr *icmp = (struct icmphdr *)pkt->parsed.transport_header;

	/* Set ports to ICMP type/code for tracking */
	pkt->parsed.src_port = icmp->type;
	pkt->parsed.dst_port = icmp->code;

	pkt->parsed.payload = pkt->parsed.transport_header +
	                      sizeof(struct icmphdr);
	pkt->parsed.payload_len = pkt->parsed.transport_len -
	                          sizeof(struct icmphdr);

	return 0;
}

int parse_http(packet_t *pkt)
{
	if (!pkt->parsed.payload || pkt->parsed.payload_len < 16)
		return -1;

	const char *payload = (const char *)pkt->parsed.payload;

	/* Check for HTTP methods */
	if (strncmp(payload, "GET ", 4) == 0) {
		pkt->parsed.is_http = true;
		pkt->parsed.http_method = strdup("GET");
	} else if (strncmp(payload, "POST ", 5) == 0) {
		pkt->parsed.is_http = true;
		pkt->parsed.http_method = strdup("POST");
	} else if (strncmp(payload, "HEAD ", 5) == 0) {
		pkt->parsed.is_http = true;
		pkt->parsed.http_method = strdup("HEAD");
	} else if (strncmp(payload, "PUT ", 4) == 0) {
		pkt->parsed.is_http = true;
		pkt->parsed.http_method = strdup("PUT");
	} else if (strncmp(payload, "DELETE ", 7) == 0) {
		pkt->parsed.is_http = true;
		pkt->parsed.http_method = strdup("DELETE");
	} else {
		return -1;
	}

	/* Extract URI */
	const char *uri_start = strchr(payload, ' ');
	if (uri_start) {
		uri_start++;
		const char *uri_end = strchr(uri_start, ' ');
		if (uri_end) {
			size_t uri_len = uri_end - uri_start;
			if (uri_len > 0 && uri_len < 2048) {
				pkt->parsed.http_uri = strndup(uri_start, uri_len);
			}
		}
	}

	/* Extract User-Agent */
	const char *ua_header = strstr(payload, "User-Agent:");
	if (ua_header) {
		const char *ua_start = ua_header + 11;
		while (*ua_start == ' ')
			ua_start++;

		const char *ua_end = strstr(ua_start, "\r\n");
		if (ua_end) {
			size_t ua_len = ua_end - ua_start;
			if (ua_len > 0 && ua_len < 512) {
				pkt->parsed.http_user_agent = strndup(ua_start, ua_len);
			}
		}
	}

	/* Extract Content-Length */
	const char *cl_header = strstr(payload, "Content-Length:");
	if (cl_header) {
		pkt->parsed.http_content_length = atoi(cl_header + 15);
	}

	return 0;
}
