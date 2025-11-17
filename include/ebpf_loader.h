#ifndef DDOS_EBPF_LOADER_H
#define DDOS_EBPF_LOADER_H

#include "common.h"

/* eBPF/XDP program structure */
typedef struct ebpf_program ebpf_program_t;

/* Load eBPF/XDP program */
ebpf_program_t *ebpf_load_program(const char *filename, const char *interface);

/* Unload eBPF/XDP program */
void ebpf_unload_program(ebpf_program_t *prog);

/* Update eBPF map (for blacklist/whitelist) */
int ebpf_update_map(ebpf_program_t *prog, const char *map_name,
                    const void *key, const void *value);

/* Delete from eBPF map */
int ebpf_delete_map(ebpf_program_t *prog, const char *map_name,
                    const void *key);

/* Get eBPF map statistics */
int ebpf_get_map_stats(ebpf_program_t *prog, const char *map_name,
                       uint64_t *packets, uint64_t *bytes);

/* Add IP to XDP blacklist */
int ebpf_blacklist_ip(ebpf_program_t *prog, const ip_addr_t *ip);

/* Remove IP from XDP blacklist */
int ebpf_whitelist_ip(ebpf_program_t *prog, const ip_addr_t *ip);

#endif /* DDOS_EBPF_LOADER_H */
