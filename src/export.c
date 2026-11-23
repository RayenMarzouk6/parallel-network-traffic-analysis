#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include "analyzer.h"

#define ULL(x) ((unsigned long long)(x))

typedef struct { uint32_t key; uint64_t flows, bytes; } Row;

static int cmp_row(const void *a, const void *b) {
    const Row *x = a, *y = b;
    if (x->flows != y->flows) return x->flows < y->flows ? 1 : -1;
    return x->key < y->key ? -1 : (x->key > y->key);
}

static FILE *open_in(const char *dir, const char *name) {
    char path[1200];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "w");
    if (!f) perror(path);
    return f;
}

static Row *map_rows(const IpMap *m, size_t *n) {
    Row *r = malloc((m->used ? m->used : 1) * sizeof(Row));
    *n = 0;
    if (!r) return NULL;
    size_t k = 0;
    for (size_t i = 0; i < m->cap; i++)
        if (m->slots[i].flows)
            r[k++] = (Row){ m->slots[i].ip, m->slots[i].flows, m->slots[i].bytes };
    *n = k;
    return r;
}

static int write_top_ips(const char *dir, const char *name, const IpMap *m, int top_n) {
    FILE *f = open_in(dir, name);
    if (!f) return -1;
    size_t n;
    Row *r = map_rows(m, &n);
    if (!r) { fclose(f); return -1; }
    qsort(r, n, sizeof(Row), cmp_row);
    fprintf(f, "rank,ip,flows,bytes\n");
    for (size_t i = 0; i < n && (int)i < top_n; i++) {
        char buf[INET_ADDRSTRLEN];
        struct in_addr a = { htonl(r[i].key) };
        inet_ntop(AF_INET, &a, buf, sizeof buf);
        fprintf(f, "%zu,%s,%llu,%llu\n", i + 1, buf, ULL(r[i].flows), ULL(r[i].bytes));
    }
    free(r);
    fclose(f);
    return 0;
}

static int write_top_ports(const char *dir, const Stats *s, int top_n) {
    FILE *f = open_in(dir, "top_dst_ports.csv");
    if (!f) return -1;
    Row *r = malloc(65536 * sizeof(Row));
    if (!r) { fclose(f); return -1; }
    size_t n = 0;
    for (int p = 0; p < 65536; p++)
        if (s->port_flows[p])
            r[n++] = (Row){ (uint32_t)p, s->port_flows[p], s->port_bytes[p] };
    qsort(r, n, sizeof(Row), cmp_row);
    fprintf(f, "rank,port,flows,bytes\n");
    for (size_t i = 0; i < n && (int)i < top_n; i++)
        fprintf(f, "%zu,%u,%llu,%llu\n", i + 1, r[i].key, ULL(r[i].flows), ULL(r[i].bytes));
    free(r);
    fclose(f);
    return 0;
}

int export_results(const char *dir, const Stats *s, const Dataset *ds, int top_n) {
    if (mkdir(dir, 0755) != 0 && errno != EEXIST) { perror(dir); return -1; }
    int rc = 0;
    FILE *f;

    if ((f = open_in(dir, "summary.csv"))) {
        size_t nports = 0;
        for (int p = 0; p < 65536; p++) if (s->port_flows[p]) nports++;
        fprintf(f, "metric,value\n");
        fprintf(f, "records_read,%zu\n", ds->lines_read);
        fprintf(f, "records_valid,%zu\n", ds->count);
        fprintf(f, "records_invalid,%zu\n", ds->invalid);
        fprintf(f, "records_blank,%zu\n", ds->blank);
        fprintf(f, "flows,%llu\n", ULL(s->flows));
        fprintf(f, "packets,%llu\n", ULL(s->packets));
        fprintf(f, "bytes,%llu\n", ULL(s->bytes));
        fprintf(f, "unique_src_ips,%zu\n", s->src.used);
        fprintf(f, "unique_dst_ips,%zu\n", s->dst.used);
        fprintf(f, "unique_dst_ports,%zu\n", nports);
        fclose(f);
    } else rc = -1;

    if ((f = open_in(dir, "protocols.csv"))) {
        const int ids[3] = { PROTO_TCP, PROTO_UDP, PROTO_ICMP };
        const char *names[3] = { "TCP", "UDP", "ICMP" };
        uint64_t named = 0, named_bytes = 0;
        fprintf(f, "protocol,flows,percent,bytes\n");
        for (int i = 0; i < 3; i++) {
            named += s->proto_flows[ids[i]];
            named_bytes += s->proto_bytes[ids[i]];
            fprintf(f, "%s,%llu,%.4f,%llu\n", names[i], ULL(s->proto_flows[ids[i]]),
                    100.0 * s->proto_flows[ids[i]] / s->flows, ULL(s->proto_bytes[ids[i]]));
        }
        fprintf(f, "Other,%llu,%.4f,%llu\n", ULL(s->flows - named),
                100.0 * (s->flows - named) / s->flows, ULL(s->bytes - named_bytes));
        fclose(f);
    } else rc = -1;

    if ((f = open_in(dir, "labels.csv"))) {
        fprintf(f, "label,flows\n");
        for (int i = 0; i < ds->n_labels; i++)
            fprintf(f, "%s,%llu\n", ds->label_names[i], ULL(s->label_flows[i]));
        fclose(f);
    } else rc = -1;

    if ((f = open_in(dir, "timeseries.csv"))) {
        fprintf(f, "window_start,flows,bytes\n");
        for (size_t i = 0; i < s->n_windows; i++) {
            if (!s->win_flows[i]) continue;
            time_t t = (time_t)((s->t0_ms + (int64_t)i * s->window_ms) / 1000);
            char tb[32];
            strftime(tb, sizeof tb, "%Y-%m-%d %H:%M:%S", gmtime(&t));
            fprintf(f, "%s,%llu,%llu\n", tb, ULL(s->win_flows[i]), ULL(s->win_bytes[i]));
        }
        fclose(f);
    } else rc = -1;

    if (write_top_ips(dir, "top_src_ips.csv", &s->src, top_n) != 0) rc = -1;
    if (write_top_ips(dir, "top_dst_ips.csv", &s->dst, top_n) != 0) rc = -1;
    if (write_top_ports(dir, s, top_n) != 0) rc = -1;
    return rc;
}
