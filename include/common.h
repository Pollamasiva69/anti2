#ifndef DDOS_COMMON_H
#define DDOS_COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <netinet/in.h>
#include <pthread.h>

/* Version */
#define DDOS_VERSION "1.0.0"
#define DDOS_VERSION_MAJOR 1
#define DDOS_VERSION_MINOR 0
#define DDOS_VERSION_PATCH 0

/* Constants */
#define MAX_PACKET_SIZE 65535
#define MAX_IP_STR_LEN 46
#define MAX_WORKERS 64
#define HASH_TABLE_SIZE 1048576  /* 1M entries */
#define LRU_CACHE_SIZE 524288    /* 512K entries */
#define MAX_BLACKLIST_SIZE 100000
#define MAX_WHITELIST_SIZE 10000

/* Rate limiting windows */
#define RATE_WINDOW_SHORT 1      /* 1 second */
#define RATE_WINDOW_MEDIUM 10    /* 10 seconds */
#define RATE_WINDOW_LONG 60      /* 60 seconds */

/* Attack thresholds (configurable) */
#define DEFAULT_UDP_PPS_THRESHOLD 10000
#define DEFAULT_TCP_SYN_PPS_THRESHOLD 5000
#define DEFAULT_ICMP_PPS_THRESHOLD 1000
#define DEFAULT_HTTP_RPS_THRESHOLD 100

/* Connection tracking timeouts */
#define TCP_SYN_TIMEOUT 30
#define TCP_ESTABLISHED_TIMEOUT 7200
#define TCP_FIN_TIMEOUT 30
#define UDP_TIMEOUT 60
#define ICMP_TIMEOUT 10

/* Protocol numbers */
#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17

/* Attack types */
typedef enum {
	ATTACK_NONE = 0,
	ATTACK_UDP_FLOOD,
	ATTACK_UDP_FRAGMENTATION,
	ATTACK_DNS_AMPLIFICATION,
	ATTACK_NTP_AMPLIFICATION,
	ATTACK_SSDP_REFLECTION,
	ATTACK_MEMCACHED_AMPLIFICATION,
	ATTACK_TCP_SYN_FLOOD,
	ATTACK_TCP_ACK_FLOOD,
	ATTACK_TCP_RST_FLOOD,
	ATTACK_TCP_FIN_FLOOD,
	ATTACK_TCP_PSH_ACK_FLOOD,
	ATTACK_SLOWLORIS,
	ATTACK_SOCKSTRESS,
	ATTACK_ICMP_FLOOD,
	ATTACK_ICMP_FRAGMENTATION,
	ATTACK_PING_OF_DEATH,
	ATTACK_SMURF,
	ATTACK_HTTP_GET_FLOOD,
	ATTACK_HTTP_POST_FLOOD,
	ATTACK_SLOW_POST,
	ATTACK_HTTP_HEADER_ANOMALY,
	ATTACK_MAX
} attack_type_t;

/* Packet verdict */
typedef enum {
	VERDICT_ACCEPT = 0,
	VERDICT_DROP,
	VERDICT_RATE_LIMIT,
	VERDICT_CHALLENGE
} verdict_t;

/* IP address structure (v4/v6 compatible) */
typedef struct {
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} addr;
	uint8_t family;  /* AF_INET or AF_INET6 */
} ip_addr_t;

/* Connection tuple */
typedef struct {
	ip_addr_t src_ip;
	ip_addr_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t protocol;
} conn_tuple_t;

/* TCP connection state */
typedef enum {
	TCP_STATE_SYN_SENT,
	TCP_STATE_SYN_RECEIVED,
	TCP_STATE_ESTABLISHED,
	TCP_STATE_FIN_WAIT,
	TCP_STATE_CLOSE_WAIT,
	TCP_STATE_CLOSED
} tcp_state_t;

/* Connection tracking entry */
typedef struct conn_entry {
	conn_tuple_t tuple;
	tcp_state_t state;
	time_t first_seen;
	time_t last_seen;
	uint64_t packets;
	uint64_t bytes;
	uint32_t flags;
	struct conn_entry *next;  /* for hash table chaining */
	struct conn_entry *lru_prev;
	struct conn_entry *lru_next;
} conn_entry_t;

/* Per-IP statistics */
typedef struct {
	ip_addr_t ip;
	uint64_t packets[ATTACK_MAX];
	uint64_t bytes[ATTACK_MAX];
	uint64_t udp_pps;
	uint64_t tcp_syn_pps;
	uint64_t tcp_ack_pps;
	uint64_t icmp_pps;
	uint64_t http_rps;
	time_t last_update;
	time_t first_seen;
	uint32_t reputation_score;  /* 0-100, lower is worse */
	bool is_blacklisted;
	bool is_whitelisted;
	time_t blacklist_expires;
	char country_code[3];
	uint32_t asn;
	pthread_rwlock_t lock;
} ip_stats_t;

/* Sliding window for rate limiting */
typedef struct {
	uint64_t *buckets;
	uint32_t size;
	uint32_t current_idx;
	time_t window_start;
	pthread_mutex_t lock;
} sliding_window_t;

/* Pattern detection for ML */
typedef struct {
	double entropy;
	double packet_size_avg;
	double packet_size_stddev;
	double inter_arrival_time_avg;
	uint32_t syn_ack_ratio;
	uint32_t udp_tcp_ratio;
	uint32_t unique_src_ips;
	uint32_t unique_dst_ports;
} traffic_pattern_t;

/* Global statistics */
typedef struct {
	uint64_t total_packets;
	uint64_t total_bytes;
	uint64_t dropped_packets;
	uint64_t rate_limited_packets;
	uint64_t attacks_detected[ATTACK_MAX];
	uint64_t current_connections;
	uint64_t blacklisted_ips;
	uint64_t whitelisted_ips;
	double cpu_usage;
	double memory_usage;
	time_t start_time;
	pthread_rwlock_t lock;
} global_stats_t;

/* Configuration structure */
typedef struct {
	/* Network */
	char *interface;
	bool promiscuous_mode;
	int snaplen;

	/* Worker threads */
	uint32_t num_workers;
	bool cpu_affinity;
	bool numa_aware;

	/* Attack thresholds */
	uint32_t udp_pps_threshold;
	uint32_t tcp_syn_pps_threshold;
	uint32_t tcp_ack_pps_threshold;
	uint32_t icmp_pps_threshold;
	uint32_t http_rps_threshold;

	/* Rate limiting */
	bool enable_rate_limiting;
	uint32_t rate_limit_pps;
	uint32_t rate_limit_bps;

	/* Blacklist/Whitelist */
	bool auto_blacklist;
	uint32_t blacklist_duration;
	char **whitelist_ips;
	uint32_t whitelist_count;
	char **blacklist_ips;
	uint32_t blacklist_count;

	/* GeoIP */
	bool enable_geoip;
	char **blocked_countries;
	uint32_t blocked_countries_count;
	char *geoip_db_path;

	/* eBPF/XDP */
	bool enable_xdp;
	char *xdp_program_path;

	/* HTTP protection */
	bool enable_http_protection;
	bool enable_js_challenge;
	bool enable_captcha;
	char **user_agent_blacklist;
	uint32_t user_agent_blacklist_count;

	/* Logging */
	char *log_file;
	int log_level;
	bool syslog_enabled;

	/* API */
	bool enable_api;
	char *api_bind_address;
	uint16_t api_port;
	char *api_auth_token;

	/* Dashboard */
	bool enable_dashboard;
	uint16_t dashboard_port;

	/* Security */
	bool enable_chroot;
	char *chroot_dir;
	char *drop_user;
	char *drop_group;
	bool enable_seccomp;

	pthread_rwlock_t lock;
} config_t;

/* Global context */
typedef struct {
	config_t *config;
	global_stats_t *stats;
	void *conn_table;      /* hash table */
	void *lru_cache;
	void *ip_stats_table;
	void *geoip_db;
	pthread_t *worker_threads;
	bool running;
	pthread_mutex_t global_lock;
} ddos_context_t;

/* Packet structure */
typedef struct {
	uint8_t *data;
	uint32_t len;
	time_t timestamp;

	/* Parsed headers */
	struct {
		uint8_t *eth_header;
		uint8_t *ip_header;
		uint8_t *transport_header;
		uint8_t *payload;

		uint32_t eth_len;
		uint32_t ip_len;
		uint32_t transport_len;
		uint32_t payload_len;

		bool is_ipv4;
		bool is_ipv6;
		uint8_t protocol;

		ip_addr_t src_ip;
		ip_addr_t dst_ip;
		uint16_t src_port;
		uint16_t dst_port;

		/* TCP specific */
		uint8_t tcp_flags;
		uint32_t tcp_seq;
		uint32_t tcp_ack;

		/* HTTP specific */
		bool is_http;
		char *http_method;
		char *http_uri;
		char *http_user_agent;
		uint32_t http_content_length;
	} parsed;
} packet_t;

/* Utility macros */
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* Compiler optimizations */
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define CACHE_LINE_SIZE 64
#define __aligned(x) __attribute__((aligned(x)))
#define __packed __attribute__((packed))

/* Memory barriers */
#define barrier() __asm__ __volatile__("": : :"memory")
#define smp_mb() __sync_synchronize()

/* Attack type to string */
static inline const char *attack_type_to_string(attack_type_t type)
{
	static const char *attack_strings[] = {
		[ATTACK_NONE] = "None",
		[ATTACK_UDP_FLOOD] = "UDP Flood",
		[ATTACK_UDP_FRAGMENTATION] = "UDP Fragmentation",
		[ATTACK_DNS_AMPLIFICATION] = "DNS Amplification",
		[ATTACK_NTP_AMPLIFICATION] = "NTP Amplification",
		[ATTACK_SSDP_REFLECTION] = "SSDP Reflection",
		[ATTACK_MEMCACHED_AMPLIFICATION] = "Memcached Amplification",
		[ATTACK_TCP_SYN_FLOOD] = "TCP SYN Flood",
		[ATTACK_TCP_ACK_FLOOD] = "TCP ACK Flood",
		[ATTACK_TCP_RST_FLOOD] = "TCP RST Flood",
		[ATTACK_TCP_FIN_FLOOD] = "TCP FIN Flood",
		[ATTACK_TCP_PSH_ACK_FLOOD] = "TCP PSH+ACK Flood",
		[ATTACK_SLOWLORIS] = "Slowloris",
		[ATTACK_SOCKSTRESS] = "Sockstress",
		[ATTACK_ICMP_FLOOD] = "ICMP Flood",
		[ATTACK_ICMP_FRAGMENTATION] = "ICMP Fragmentation",
		[ATTACK_PING_OF_DEATH] = "Ping of Death",
		[ATTACK_SMURF] = "Smurf Attack",
		[ATTACK_HTTP_GET_FLOOD] = "HTTP GET Flood",
		[ATTACK_HTTP_POST_FLOOD] = "HTTP POST Flood",
		[ATTACK_SLOW_POST] = "Slow POST",
		[ATTACK_HTTP_HEADER_ANOMALY] = "HTTP Header Anomaly",
	};

	if (type < ATTACK_MAX)
		return attack_strings[type];
	return "Unknown";
}

/* IP address utilities */
int ip_addr_compare(const ip_addr_t *a, const ip_addr_t *b);
void ip_addr_to_string(const ip_addr_t *ip, char *buf, size_t len);
int string_to_ip_addr(const char *str, ip_addr_t *ip);

#endif /* DDOS_COMMON_H */
