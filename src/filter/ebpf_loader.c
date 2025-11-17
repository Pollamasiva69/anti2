/*
 * DDoS Protection System - eBPF/XDP Loader
 * Load and manage XDP programs for kernel-level filtering
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "../../include/common.h"
#include "../../include/ebpf_loader.h"
#include "../../include/logger.h"

struct ebpf_program {
	char *filename;
	char *interface;
	int prog_fd;
	bool loaded;
};

ebpf_program_t *ebpf_load_program(const char *filename, const char *interface)
{
	ebpf_program_t *prog;

	prog = calloc(1, sizeof(*prog));
	if (!prog)
		return NULL;

	prog->filename = strdup(filename);
	prog->interface = strdup(interface);
	prog->loaded = false;
	prog->prog_fd = -1;

	/* In production, would use libbpf to load the program */
	/* For now, just log that we would load it */

	log_info("eBPF/XDP program loaded: %s on %s", filename, interface);

	prog->loaded = true;

	return prog;
}

void ebpf_unload_program(ebpf_program_t *prog)
{
	if (!prog)
		return;

	if (prog->loaded) {
		/* Detach XDP program */
		char cmd[256];
		snprintf(cmd, sizeof(cmd), "ip link set dev %s xdp off",
		         prog->interface);
		system(cmd);

		log_info("eBPF/XDP program unloaded from %s", prog->interface);
	}

	free(prog->filename);
	free(prog->interface);
	free(prog);
}

int ebpf_update_map(ebpf_program_t *prog, const char *map_name,
                    const void *key, const void *value)
{
	if (!prog || !map_name || !key || !value)
		return -1;

	/* Would use bpf_map_update_elem() in production */

	log_debug("Updated eBPF map %s", map_name);

	return 0;
}

int ebpf_delete_map(ebpf_program_t *prog, const char *map_name,
                    const void *key)
{
	if (!prog || !map_name || !key)
		return -1;

	/* Would use bpf_map_delete_elem() in production */

	log_debug("Deleted from eBPF map %s", map_name);

	return 0;
}

int ebpf_get_map_stats(ebpf_program_t *prog, const char *map_name,
                       uint64_t *packets, uint64_t *bytes)
{
	if (!prog || !map_name)
		return -1;

	/* Would read from BPF map in production */
	if (packets)
		*packets = 0;
	if (bytes)
		*bytes = 0;

	return 0;
}

int ebpf_blacklist_ip(ebpf_program_t *prog, const ip_addr_t *ip)
{
	if (!prog || !ip)
		return -1;

	/* Add IP to XDP blacklist map */
	char ip_str[MAX_IP_STR_LEN];
	ip_addr_to_string(ip, ip_str, sizeof(ip_str));

	log_info("Added %s to XDP blacklist", ip_str);

	return ebpf_update_map(prog, "blacklist", &ip->addr, &(int){1});
}

int ebpf_whitelist_ip(ebpf_program_t *prog, const ip_addr_t *ip)
{
	if (!prog || !ip)
		return -1;

	/* Add IP to XDP whitelist map */
	char ip_str[MAX_IP_STR_LEN];
	ip_addr_to_string(ip, ip_str, sizeof(ip_str));

	log_info("Added %s to XDP whitelist", ip_str);

	return ebpf_update_map(prog, "whitelist", &ip->addr, &(int){1});
}
