#ifndef DETECTION_H
#define DETECTION_H

#include <stdint.h>
#include <stddef.h>
#include "packet_record.h"
#include "analyzer.h"

enum { ALERT_PORT_SCAN = 0, ALERT_SPIKE_FLOWS = 1, ALERT_SPIKE_BYTES = 2 };

typedef struct {
    int      type;
    int64_t  win_start_ms, win_end_ms;
    uint32_t src_ip, dst_ip;      /* 0 pour les pics (pas d'IP) */
    uint64_t value;               /* ports distincts, flux ou octets */
    double   threshold;
    double   score;               /* valeur / seuil */
    uint32_t n_records;           /* flux du groupe (scans) */
    uint32_t n_scan_records;      /* dont labellises PortScan */
} Alert;

typedef struct { Alert *a; size_t n, cap; } AlertList;

void     alerts_init(AlertList *l);
void     alerts_free(AlertList *l);
void     alerts_push(AlertList *l, const Alert *x);
void     alerts_append(AlertList *dst, const AlertList *src);
void     alerts_sort(AlertList *l);               /* ordre canonique */
uint64_t alerts_checksum(const AlertList *l);     /* independant de l'ordre */
int      alerts_write_csv(const char *path, const AlertList *l);

/* Traite uniquement les groupes (src,dst) de la partition `part` sur `nparts`.
   Sequentiel : part = 0, nparts = 1. */
void detect_port_scans(const Dataset *ds, int64_t t0_ms, int64_t window_ms,
                       unsigned threshold, int scan_label,
                       int part, int nparts, AlertList *out);

void detect_spikes(const Stats *s, const uint64_t *series, int type,
                   int baseline_n, double factor, uint64_t min_value,
                   AlertList *out);

void evaluate_port_scans(const Dataset *ds, const AlertList *al, int scan_label);
void print_alert_summary(const AlertList *al, int top_n);

void detect_port_scans_parallel(const Dataset *ds, int64_t t0_ms, int64_t window_ms,
                                unsigned threshold, int scan_label, int threads,
                                AlertList *out);

void detect_set_ignore_reverse(int on);

#endif
