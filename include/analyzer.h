#ifndef ANALYZER_H
#define ANALYZER_H

#include <stdint.h>
#include <stddef.h>
#include "packet_record.h"

/* Table de hachage IP -> compteurs (adressage ouvert).
   Un slot est vide quand flows == 0 (on n'insere jamais flows == 0). */
typedef struct { uint32_t ip; uint64_t flows; uint64_t bytes; } IpEntry;
typedef struct { IpEntry *slots; size_t cap, used; } IpMap;

void ipmap_init(IpMap *m, size_t cap);
void ipmap_free(IpMap *m);
void ipmap_add(IpMap *m, uint32_t ip, uint64_t flows, uint64_t bytes);
void ipmap_merge(IpMap *dst, const IpMap *src);

typedef struct {
    uint64_t flows, packets, bytes;
    uint64_t proto_flows[256], proto_bytes[256];
    uint64_t *port_flows, *port_bytes;   /* 65536 : port destination, TCP/UDP */
    uint64_t label_flows[MAX_LABELS];
    IpMap src, dst;
    int64_t  t0_ms, window_ms;
    size_t   n_windows;
    uint64_t *win_flows, *win_bytes;
} Stats;

Stats *stats_create(int64_t t0_ms, int64_t window_ms, size_t n_windows);
void   stats_destroy(Stats *s);
void   stats_add_record(Stats *s, const PacketRecord *r);  /* meme logique seq/parallele */
void   stats_merge(Stats *dst, const Stats *src);          /* pour la version OpenMP */
uint64_t stats_checksum(const Stats *s);
void   print_report(const Stats *s, const Dataset *ds, int top_n);
int export_results(const char *dir, const Stats *s, const Dataset *ds, int top_n);

void analyze_sequential(const Dataset *ds, Stats *s);

void analyze_parallel(const Dataset *ds, Stats *s, int threads);

#endif
