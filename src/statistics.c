#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include "analyzer.h"

#define ULL(x) ((unsigned long long)(x))

Stats *stats_create(int64_t t0_ms, int64_t window_ms, size_t n_windows) {
    Stats *s = calloc(1, sizeof(Stats));
    if (!s) { fprintf(stderr, "Memoire insuffisante\n"); exit(1); }
    s->t0_ms = t0_ms;
    s->window_ms = window_ms;
    s->n_windows = n_windows;
    s->port_flows = calloc(65536, sizeof(uint64_t));
    s->port_bytes = calloc(65536, sizeof(uint64_t));
    s->win_flows  = calloc(n_windows, sizeof(uint64_t));
    s->win_bytes  = calloc(n_windows, sizeof(uint64_t));
    if (!s->port_flows || !s->port_bytes || !s->win_flows || !s->win_bytes) {
        fprintf(stderr, "Memoire insuffisante\n"); exit(1);
    }
    ipmap_init(&s->src, 1 << 12);
    ipmap_init(&s->dst, 1 << 12);
    return s;
}

void stats_destroy(Stats *s) {
    if (!s) return;
    free(s->port_flows); free(s->port_bytes);
    free(s->win_flows);  free(s->win_bytes);
    ipmap_free(&s->src); ipmap_free(&s->dst);
    free(s);
}

/* Definition UNIQUE des statistiques : utilisee par le sequentiel ET le parallele. */
void stats_add_record(Stats *s, const PacketRecord *r) {
    s->flows++;
    s->packets += r->packets;
    s->bytes   += r->size_bytes;
    s->proto_flows[r->protocol]++;
    s->proto_bytes[r->protocol] += r->size_bytes;
    if (r->has_ports) {
        s->port_flows[r->dst_port]++;
        s->port_bytes[r->dst_port] += r->size_bytes;
    }
    s->label_flows[r->label]++;
    ipmap_add(&s->src, r->src_ip, 1, r->size_bytes);
    ipmap_add(&s->dst, r->dst_ip, 1, r->size_bytes);
    size_t w = (size_t)((r->timestamp_ms - s->t0_ms) / s->window_ms);
    s->win_flows[w]++;
    s->win_bytes[w] += r->size_bytes;
}

void stats_merge(Stats *d, const Stats *o) {
    d->flows += o->flows; d->packets += o->packets; d->bytes += o->bytes;
    for (int i = 0; i < 256; i++) {
        d->proto_flows[i] += o->proto_flows[i];
        d->proto_bytes[i] += o->proto_bytes[i];
    }
    for (int i = 0; i < 65536; i++) {
        d->port_flows[i] += o->port_flows[i];
        d->port_bytes[i] += o->port_bytes[i];
    }
    for (int i = 0; i < MAX_LABELS; i++) d->label_flows[i] += o->label_flows[i];
    for (size_t i = 0; i < d->n_windows; i++) {
        d->win_flows[i] += o->win_flows[i];
        d->win_bytes[i] += o->win_bytes[i];
    }
    ipmap_merge(&d->src, &o->src);
    ipmap_merge(&d->dst, &o->dst);
}

static uint64_t mix(uint64_t a, uint64_t b, uint64_t c) {
    uint64_t h = a * 0x9E3779B97F4A7C15ULL;
    h ^= (b + 0x7F4A7C15ULL) * 0xC2B2AE3D27D4EB4FULL;
    h ^= (c + 0x165667B1ULL) * 0x94D049BB133111EBULL;
    h ^= h >> 31;
    return h * 0xBF58476D1CE4E5B9ULL;
}

/* Checksum independant de l'ordre : identique si les statistiques sont identiques. */
uint64_t stats_checksum(const Stats *s) {
    uint64_t h = mix(s->flows, s->packets, s->bytes);
    for (int i = 0; i < 256; i++)       h += mix(1000 + i, s->proto_flows[i], s->proto_bytes[i]);
    for (int i = 0; i < 65536; i++)     h += mix(2000 + i, s->port_flows[i], s->port_bytes[i]);
    for (int i = 0; i < MAX_LABELS; i++) h += mix(3000 + i, s->label_flows[i], 0);
    for (size_t i = 0; i < s->n_windows; i++) h += mix(4000 + i, s->win_flows[i], s->win_bytes[i]);
    for (size_t i = 0; i < s->src.cap; i++)
        if (s->src.slots[i].flows) h += mix(5, s->src.slots[i].ip, s->src.slots[i].flows ^ (s->src.slots[i].bytes << 1));
    for (size_t i = 0; i < s->dst.cap; i++)
        if (s->dst.slots[i].flows) h += mix(6, s->dst.slots[i].ip, s->dst.slots[i].flows ^ (s->dst.slots[i].bytes << 1));
    return h;
}

/* ---------- Affichage ---------- */

static int cmp_flows(const void *a, const void *b) {
    const IpEntry *x = a, *y = b;
    if (x->flows != y->flows) return x->flows < y->flows ? 1 : -1;
    return x->ip < y->ip ? -1 : (x->ip > y->ip);          /* departage deterministe */
}
static int cmp_bytes(const void *a, const void *b) {
    const IpEntry *x = a, *y = b;
    if (x->bytes != y->bytes) return x->bytes < y->bytes ? 1 : -1;
    return x->ip < y->ip ? -1 : (x->ip > y->ip);
}

static void print_top(const char *title, IpEntry *arr, size_t n, int top_n,
                      int is_ip, int by_bytes) {
    qsort(arr, n, sizeof(IpEntry), by_bytes ? cmp_bytes : cmp_flows);
    printf("\n%s\n", title);
    for (size_t i = 0; i < n && (int)i < top_n; i++) {
        char buf[INET_ADDRSTRLEN];
        if (is_ip) {
            struct in_addr a = { htonl(arr[i].ip) };
            inet_ntop(AF_INET, &a, buf, sizeof buf);
        } else {
            snprintf(buf, sizeof buf, "%u", arr[i].ip);
        }
        printf("  %2zu. %-16s %12llu flux %16llu octets\n",
               i + 1, buf, ULL(arr[i].flows), ULL(arr[i].bytes));
    }
}

static IpEntry *ipmap_to_array(const IpMap *m, size_t *n) {
    IpEntry *a = malloc((m->used ? m->used : 1) * sizeof(IpEntry));
    size_t k = 0;
    for (size_t i = 0; i < m->cap; i++) if (m->slots[i].flows) a[k++] = m->slots[i];
    *n = k;
    return a;
}

void print_report(const Stats *s, const Dataset *ds, int top_n) {
    printf("\n===== STATISTIQUES GENERALES =====\n");
    printf("Flux analyses      : %llu\n", ULL(s->flows));
    printf("Paquets (total)    : %llu\n", ULL(s->packets));
    printf("Octets (total)     : %llu\n", ULL(s->bytes));
    printf("IP sources uniques : %zu\n", s->src.used);
    printf("IP dest. uniques   : %zu\n", s->dst.used);
    size_t nports = 0;
    for (int i = 0; i < 65536; i++) if (s->port_flows[i]) nports++;
    printf("Ports dest. uniques: %zu\n", nports);

    printf("\n===== PROTOCOLES =====\n");
    uint64_t named = 0;
    for (int p = 0; p < 256; p++) {
        const char *name = p == 1 ? "ICMP" : p == 6 ? "TCP" : p == 17 ? "UDP" : NULL;
        if (!name) continue;
        named += s->proto_flows[p];
        printf("  %-6s %12llu flux (%5.2f %%) %16llu octets\n", name,
               ULL(s->proto_flows[p]), 100.0 * s->proto_flows[p] / s->flows,
               ULL(s->proto_bytes[p]));
    }
    uint64_t other = s->flows - named;
    printf("  %-6s %12llu flux (%5.2f %%)\n", "Autres", ULL(other), 100.0 * other / s->flows);

    printf("\n===== LABELS (verite terrain) =====\n");
    for (int i = 0; i < ds->n_labels; i++)
        printf("  %-28s %10llu\n", ds->label_names[i], ULL(s->label_flows[i]));

    size_t n;
    IpEntry *a = ipmap_to_array(&s->src, &n);
    print_top("Top IP sources (par flux)", a, n, top_n, 1, 0);
    print_top("Top IP sources (par octets)", a, n, top_n, 1, 1);
    free(a);
    a = ipmap_to_array(&s->dst, &n);
    print_top("Top IP destinations (par flux)", a, n, top_n, 1, 0);
    print_top("Top IP destinations (par octets)", a, n, top_n, 1, 1);
    free(a);

    a = malloc(65536 * sizeof(IpEntry));
    n = 0;
    for (int p = 0; p < 65536; p++)
        if (s->port_flows[p]) a[n++] = (IpEntry){ (uint32_t)p, s->port_flows[p], s->port_bytes[p] };
    print_top("Top ports destination (par flux)", a, n, top_n, 0, 0);
    free(a);

    printf("\n===== SERIE TEMPORELLE (fenetre = %lld s) =====\n", (long long)(s->window_ms / 1000));
    size_t active = 0, peak = 0;
    for (size_t i = 0; i < s->n_windows; i++) {
        if (s->win_flows[i]) active++;
        if (s->win_flows[i] > s->win_flows[peak]) peak = i;
    }
    time_t tp = (time_t)((s->t0_ms + (int64_t)peak * s->window_ms) / 1000);
    char tb[32];
    strftime(tb, sizeof tb, "%Y-%m-%d %H:%M", gmtime(&tp));
    printf("Fenetres totales   : %zu (dont %zu non vides)\n", s->n_windows, active);
    printf("Fenetre la + chargee: %s -> %llu flux, %llu octets\n",
           tb, ULL(s->win_flows[peak]), ULL(s->win_bytes[peak]));
}
