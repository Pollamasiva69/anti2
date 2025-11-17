#ifndef DDOS_ANALYZER_H
#define DDOS_ANALYZER_H

#include "common.h"

/* Traffic analyzer structure */
typedef struct traffic_analyzer traffic_analyzer_t;

/* Initialize traffic analyzer */
traffic_analyzer_t *analyzer_init(ddos_context_t *ctx);

/* Cleanup traffic analyzer */
void analyzer_cleanup(traffic_analyzer_t *analyzer);

/* Analyze packet and update statistics */
verdict_t analyzer_process_packet(traffic_analyzer_t *analyzer, packet_t *pkt);

/* Get or create IP statistics */
ip_stats_t *analyzer_get_ip_stats(traffic_analyzer_t *analyzer,
                                   const ip_addr_t *ip);

/* Update IP reputation score */
void analyzer_update_reputation(traffic_analyzer_t *analyzer,
                                const ip_addr_t *ip, int delta);

/* Detect traffic patterns */
int analyzer_detect_patterns(traffic_analyzer_t *analyzer,
                             traffic_pattern_t *pattern);

/* Calculate traffic entropy */
double analyzer_calculate_entropy(traffic_analyzer_t *analyzer);

/* Baseline analysis */
int analyzer_update_baseline(traffic_analyzer_t *analyzer);
bool analyzer_is_anomaly(traffic_analyzer_t *analyzer,
                         const traffic_pattern_t *pattern);

/* Machine learning */
int analyzer_ml_train(traffic_analyzer_t *analyzer);
attack_type_t analyzer_ml_classify(traffic_analyzer_t *analyzer,
                                    const packet_t *pkt);

#endif /* DDOS_ANALYZER_H */
