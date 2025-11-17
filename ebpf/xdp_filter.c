/*
 * DDoS Protection System - XDP Filter Program
 * Kernel-level packet filtering for maximum performance
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* BPF maps */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 100000);
	__type(key, __u32);      /* IPv4 address */
	__type(value, __u64);    /* timestamp */
} blacklist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u32);      /* IPv4 address */
	__type(value, __u8);     /* dummy value */
} whitelist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

/* Statistics keys */
#define STAT_TOTAL_PACKETS  0
#define STAT_DROPPED_PACKETS 1
#define STAT_PASSED_PACKETS  2
#define STAT_SYN_PACKETS     3
#define STAT_UDP_PACKETS     4
#define STAT_ICMP_PACKETS    5

/* Helper to update statistics */
static __always_inline void update_stat(__u32 key, __u64 delta)
{
	__u64 *value = bpf_map_lookup_elem(&stats, &key);
	if (value) {
		__sync_fetch_and_add(value, delta);
	}
}

/* Parse Ethernet header */
static __always_inline int parse_eth(struct xdp_md *ctx,
                                      struct ethhdr **eth)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	*eth = data;

	if ((void *)(*eth + 1) > data_end)
		return -1;

	return 0;
}

/* Parse IPv4 header */
static __always_inline int parse_ipv4(struct xdp_md *ctx,
                                       struct iphdr **iph)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	*iph = data + sizeof(struct ethhdr);

	if ((void *)(*iph + 1) > data_end)
		return -1;

	/* Verify IP header length */
	if ((*iph)->ihl < 5)
		return -1;

	return 0;
}

/* XDP program main */
SEC("xdp")
int xdp_ddos_filter(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth;
	struct iphdr *iph;

	/* Update total packets counter */
	update_stat(STAT_TOTAL_PACKETS, 1);

	/* Parse Ethernet header */
	if (parse_eth(ctx, &eth) < 0)
		goto pass;

	/* Only handle IPv4 for now */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		goto pass;

	/* Parse IP header */
	if (parse_ipv4(ctx, &iph) < 0)
		goto drop;

	__u32 src_ip = iph->saddr;

	/* Check whitelist first */
	if (bpf_map_lookup_elem(&whitelist, &src_ip)) {
		goto pass;
	}

	/* Check blacklist */
	__u64 *blocked_time = bpf_map_lookup_elem(&blacklist, &src_ip);
	if (blocked_time) {
		/* TODO: Check expiration time */
		update_stat(STAT_DROPPED_PACKETS, 1);
		goto drop;
	}

	/* Protocol-specific filtering */
	switch (iph->protocol) {
	case IPPROTO_TCP: {
		struct tcphdr *tcp = (void *)iph + (iph->ihl * 4);

		if ((void *)(tcp + 1) > data_end)
			goto drop;

		/* Count SYN packets */
		if (tcp->syn && !tcp->ack) {
			update_stat(STAT_SYN_PACKETS, 1);
		}

		/* Block invalid flag combinations */
		if (tcp->syn && tcp->fin)
			goto drop;

		if (tcp->syn && tcp->rst)
			goto drop;

		/* Block NULL scan (no flags) */
		if (!tcp->syn && !tcp->ack && !tcp->fin &&
		    !tcp->rst && !tcp->psh && !tcp->urg)
			goto drop;

		break;
	}

	case IPPROTO_UDP: {
		struct udphdr *udp = (void *)iph + (iph->ihl * 4);

		if ((void *)(udp + 1) > data_end)
			goto drop;

		update_stat(STAT_UDP_PACKETS, 1);

		/* Block common reflection ports as source */
		__u16 sport = bpf_ntohs(udp->source);

		if (sport == 53 || sport == 123 || sport == 1900 ||
		    sport == 11211) {
			/* Potential amplification attack */
			__u16 payload_len = bpf_ntohs(udp->len) - sizeof(*udp);

			/* Large responses from these ports = likely attack */
			if (payload_len > 512) {
				goto drop;
			}
		}

		break;
	}

	case IPPROTO_ICMP: {
		struct icmphdr *icmp = (void *)iph + (iph->ihl * 4);

		if ((void *)(icmp + 1) > data_end)
			goto drop;

		update_stat(STAT_ICMP_PACKETS, 1);

		/* Block ICMP redirect */
		if (icmp->type == ICMP_REDIRECT)
			goto drop;

		/* Detect ping of death (fragmentation + large size) */
		if (bpf_ntohs(iph->tot_len) > 1500)
			goto drop;

		break;
	}

	default:
		/* Unknown protocol */
		break;
	}

	/* Fragment checks */
	__u16 frag_off = bpf_ntohs(iph->frag_off);
	if ((frag_off & 0x1FFF) || (frag_off & 0x2000)) {
		/* Fragmented packet - be suspicious */
		/* Could implement more sophisticated fragment tracking */
	}

pass:
	update_stat(STAT_PASSED_PACKETS, 1);
	return XDP_PASS;

drop:
	update_stat(STAT_DROPPED_PACKETS, 1);
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
