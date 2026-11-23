#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include "detection.h"

#define ULL(x) ((unsigned long long)(x))

static const char *type_name(int t) {
    static const char *names[] = { "port_scan", "traffic_spike_flows", "traffic_spike_bytes" };
    return names[t];
}

/* ---------- liste d'alertes ---------- */

void alerts_init(AlertList *l) { l->a = NULL; l->n = l->cap = 0; }
void alerts_free(AlertList *l) { free(l->a); alerts_init(l); }

void alerts_push(AlertList *l, const Alert *x) {
    if (l->n == l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 256;
        Alert *na = realloc(l->a, nc * sizeof(Alert));
        if (!na) { fprintf(stderr, "Memoire insuffisante (alertes)\n"); exit(1); }
        l->a = na;
        l->cap = nc;
    }
    l->a[l->n++] = *x;
}

void alerts_append(AlertList *d, const AlertList *s) {
    for (size_t i = 0; i < s->n; i++) alerts_push(d, &s->a[i]);
}

static int cmp_alert(const void *p, const void *q) {
    const Alert *a = p, *b = q;
    if (a->win_start_ms != b->win_start_ms) return a->win_start_ms < b->win_start_ms ? -1 : 1;
    if (a->type != b->type) return a->type - b->type;
    if (a->src_ip != b->src_ip) return a->src_ip < b->src_ip ? -1 : 1;
    if (a->dst_ip != b->dst_ip) return a->dst_ip < b->dst_ip ? -1 : 1;
    return 0;
}

static int cmp_score_desc(const void *p, const void *q) {
    const Alert *a = p, *b = q;
    if (a->score != b->score) return a->score < b->score ? 1 : -1;
    return cmp_alert(a, b);
}

void alerts_sort(AlertList *l) {
    if (l->n) qsort(l->a, l->n, sizeof(Alert), cmp_alert);
}

uint64_t alerts_checksum(const AlertList *l) {
    uint64_t h = 0;
    for (size_t i = 0; i < l->n; i++) {
        const Alert *a = &l->a[i];
        uint64_t x = (uint64_t)a->type * 0x9E3779B97F4A7C15ULL;
        x ^= ((uint64_t)a->win_start_ms + 0x7F4A7C15ULL) * 0xC2B2AE3D27D4EB4FULL;
        x ^= ((((uint64_t)a->src_ip) << 32) | a->dst_ip) * 0x94D049BB133111EBULL;
        x ^= (a->value + 0x165667B1ULL) * 0xBF58476D1CE4E5B9ULL;
        x ^= (uint64_t)a->n_records * 0xD6E8FEB86659FD93ULL;
        x ^= x >> 29;
        h += x * 0x9E3779B97F4A7C15ULL;
    }
    return h ^ l->n;
}

static void fmt_time(int64_t ms, char *buf, size_t n) {
    time_t t = (time_t)(ms / 1000);
    strftime(buf, n, "%Y-%m-%d %H:%M", gmtime(&t));
}

static void fmt_ip(uint32_t ip, char *buf, const char *none) {
    if (!ip) { strcpy(buf, none); return; }
    struct in_addr a = { htonl(ip) };
    inet_ntop(AF_INET, &a, buf, INET_ADDRSTRLEN);
}

int alerts_write_csv(const char *path, const AlertList *l) {
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); return -1; }
    fprintf(f, "type,window_start,window_end,src_ip,dst_ip,value,threshold,score,"
               "severity,flows_in_group,portscan_labeled\n");
    for (size_t i = 0; i < l->n; i++) {
        const Alert *a = &l->a[i];
        char ts[32], te[32], sb[INET_ADDRSTRLEN + 1], db[INET_ADDRSTRLEN + 1];
        fmt_time(a->win_start_ms, ts, sizeof ts);
        fmt_time(a->win_end_ms, te, sizeof te);
        fmt_ip(a->src_ip, sb, "");
        fmt_ip(a->dst_ip, db, "");
        const char *sev = a->score < 2.0 ? "low" : a->score < 5.0 ? "medium" : "high";
        fprintf(f, "%s,%s,%s,%s,%s,%llu,%.2f,%.2f,%s,%u,%u\n",
                type_name(a->type), ts, te, sb, db, ULL(a->value),
                a->threshold, a->score, sev, a->n_records, a->n_scan_records);
    }
    fclose(f);
    return 0;
}

/* ---------- detection de scans de ports ---------- */

typedef struct { uint32_t src, dst, win; uint16_t port; uint8_t scan; } ScanKey;

static int cmp_key(const void *p, const void *q) {
    const ScanKey *a = p, *b = q;
    if (a->src != b->src) return a->src < b->src ? -1 : 1;
    if (a->dst != b->dst) return a->dst < b->dst ? -1 : 1;
    if (a->win != b->win) return a->win < b->win ? -1 : 1;
    if (a->port != b->port) return a->port < b->port ? -1 : 1;
    return 0;
}

static uint32_t hash_pair(uint32_t a, uint32_t b) {
    uint32_t x = (a * 0x9E3779B1u) ^ ((b + 0x7F4A7C15u) * 0x85EBCA6Bu);
    x ^= x >> 15; x *= 0x2C1B3C6Du; x ^= x >> 12;
    return x;
}

static int g_ignore_reverse = 0;   /* lu seulement, jamais modifie pendant l'analyse */
void detect_set_ignore_reverse(int on) { g_ignore_reverse = on; }

/* Un groupe (src,dst) appartient a une seule partition : pas de conflit entre threads. */
/* Un groupe (src,dst,fenetre) appartient a une seule partition : pas de conflit entre threads. */
static inline int in_part(const PacketRecord *r, int part, int nparts,
                          int64_t t0_ms, int64_t window_ms) {
    if (!r->has_ports) return 0;
    if (g_ignore_reverse && r->src_port < 1024 && r->dst_port >= 1024) return 0;
    if (nparts <= 1) return 1;
    uint32_t win = (uint32_t)((r->timestamp_ms - t0_ms) / window_ms);
    return (int)(hash_pair(hash_pair(r->src_ip, r->dst_ip), win) % (uint32_t)nparts) == part;
}

void detect_port_scans(const Dataset *ds, int64_t t0_ms, int64_t window_ms,
                       unsigned threshold, int scan_label,
                       int part, int nparts, AlertList *out) {
    size_t n = 0;
    for (size_t i = 0; i < ds->count; i++)
        if (in_part(&ds->records[i], part, nparts, t0_ms, window_ms)) n++;
    if (n == 0) return;

    ScanKey *k = malloc(n * sizeof(ScanKey));
    if (!k) { fprintf(stderr, "Memoire insuffisante (scan)\n"); exit(1); }

    size_t m = 0;
    for (size_t i = 0; i < ds->count; i++) {
        const PacketRecord *r = &ds->records[i];
        if (!in_part(r, part, nparts, t0_ms, window_ms)) continue;
        k[m].src  = r->src_ip;
        k[m].dst  = r->dst_ip;
        k[m].win  = (uint32_t)((r->timestamp_ms - t0_ms) / window_ms);
        k[m].port = r->dst_port;
        k[m].scan = (uint8_t)(r->label == scan_label);
        m++;
    }

    qsort(k, n, sizeof(ScanKey), cmp_key);

    size_t i = 0;
    while (i < n) {
        size_t j = i;
        unsigned distinct = 0, nscan = 0;
        while (j < n && k[j].src == k[i].src && k[j].dst == k[i].dst && k[j].win == k[i].win) {
            if (j == i || k[j].port != k[j - 1].port) distinct++;
            nscan += k[j].scan;
            j++;
        }
        if (distinct >= threshold) {
            Alert a;
            memset(&a, 0, sizeof a);
            a.type = ALERT_PORT_SCAN;
            a.win_start_ms = t0_ms + (int64_t)k[i].win * window_ms;
            a.win_end_ms = a.win_start_ms + window_ms;
            a.src_ip = k[i].src;
            a.dst_ip = k[i].dst;
            a.value = distinct;
            a.threshold = threshold;
            a.score = (double)distinct / threshold;
            a.n_records = (uint32_t)(j - i);
            a.n_scan_records = nscan;
            alerts_push(out, &a);
        }
        i = j;
    }
    free(k);
}

/* ---------- detection de pics de trafic ---------- */

void detect_spikes(const Stats *s, const uint64_t *series, int type,
                   int baseline_n, double factor, uint64_t min_value,
                   AlertList *out) {
    for (size_t i = 0; i < s->n_windows; i++) {
        if (series[i] == 0 || series[i] < min_value) continue;

        /* baseline = moyenne des `baseline_n` fenetres NON VIDES precedentes */
        double sum = 0;
        int got = 0;
        for (size_t j = i; j > 0 && got < baseline_n; j--)
            if (series[j - 1]) { sum += (double)series[j - 1]; got++; }
        if (got < 3) continue;

        double thr = factor * (sum / got);
        if ((double)series[i] > thr) {
            Alert a;
            memset(&a, 0, sizeof a);
            a.type = type;
            a.win_start_ms = s->t0_ms + (int64_t)i * s->window_ms;
            a.win_end_ms = a.win_start_ms + s->window_ms;
            a.value = series[i];
            a.threshold = thr;
            a.score = (double)series[i] / thr;
            alerts_push(out, &a);
        }
    }
}

/* ---------- evaluation et affichage ---------- */

void evaluate_port_scans(const Dataset *ds, const AlertList *al, int scan_label) {
    printf("\n===== EVALUATION DES SCANS DE PORTS (niveau flux) =====\n");
    if (scan_label < 0) {
        printf("Pas de label PortScan dans ces donnees : evaluation impossible.\n");
        return;
    }
    uint64_t total = 0, tp = 0, fp = 0;
    for (size_t i = 0; i < ds->count; i++) total += (ds->records[i].label == scan_label);
    for (size_t i = 0; i < al->n; i++) {
        if (al->a[i].type != ALERT_PORT_SCAN) continue;
        tp += al->a[i].n_scan_records;
        fp += al->a[i].n_records - al->a[i].n_scan_records;
    }
    uint64_t fn = total - tp;
    double p  = (tp + fp) ? (double)tp / (double)(tp + fp) : 0.0;
    double r  = total ? (double)tp / (double)total : 0.0;
    double f1 = (p + r) > 0 ? 2 * p * r / (p + r) : 0.0;
    printf("Regle : un flux est detecte s'il appartient a un groupe (src,dst,fenetre) en alerte.\n");
    printf("Verite terrain : label PortScan (%llu flux)\n", ULL(total));
    printf("TP = %llu   FP = %llu   FN = %llu\n", ULL(tp), ULL(fp), ULL(fn));
    printf("Precision = %.4f   Rappel = %.4f   F1 = %.4f\n", p, r, f1);
}

void print_alert_summary(const AlertList *al, int top_n) {
    size_t cnt[3] = {0, 0, 0};
    for (size_t i = 0; i < al->n; i++) cnt[al->a[i].type]++;
    printf("\n===== ALERTES =====\n");
    printf("Scans de ports possibles : %zu\n", cnt[ALERT_PORT_SCAN]);
    printf("Pics de flux             : %zu\n", cnt[ALERT_SPIKE_FLOWS]);
    printf("Pics d'octets            : %zu\n", cnt[ALERT_SPIKE_BYTES]);
    if (!al->n) return;

    Alert *c = malloc(al->n * sizeof(Alert));
    if (!c) return;
    memcpy(c, al->a, al->n * sizeof(Alert));
    qsort(c, al->n, sizeof(Alert), cmp_score_desc);

    printf("\nTop %d alertes (score = valeur / seuil)\n", top_n);
    for (size_t i = 0; i < al->n && (int)i < top_n; i++) {
        char ts[32], sb[INET_ADDRSTRLEN + 1], db[INET_ADDRSTRLEN + 1];
        fmt_time(c[i].win_start_ms, ts, sizeof ts);
        fmt_ip(c[i].src_ip, sb, "-");
        fmt_ip(c[i].dst_ip, db, "-");
        printf("  %-20s %s  %-15s -> %-15s valeur=%llu seuil=%.1f score=%.1f\n",
               type_name(c[i].type), ts, sb, db, ULL(c[i].value), c[i].threshold, c[i].score);
    }
    free(c);
}
