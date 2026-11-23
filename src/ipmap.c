#include <stdio.h>
#include <stdlib.h>
#include "analyzer.h"

static size_t hash32(uint32_t x) {
    x ^= x >> 16; x *= 0x7feb352dU;
    x ^= x >> 15; x *= 0x846ca68bU;
    x ^= x >> 16;
    return x;
}

void ipmap_init(IpMap *m, size_t cap) {
    m->cap = cap;
    m->used = 0;
    m->slots = calloc(cap, sizeof(IpEntry));
    if (!m->slots) { fprintf(stderr, "Memoire insuffisante (ipmap)\n"); exit(1); }
}

void ipmap_free(IpMap *m) { free(m->slots); m->slots = NULL; m->cap = m->used = 0; }

static void ipmap_grow(IpMap *m) {
    IpMap n;
    ipmap_init(&n, m->cap * 2);
    for (size_t i = 0; i < m->cap; i++)
        if (m->slots[i].flows)
            ipmap_add(&n, m->slots[i].ip, m->slots[i].flows, m->slots[i].bytes);
    free(m->slots);
    *m = n;
}

void ipmap_add(IpMap *m, uint32_t ip, uint64_t flows, uint64_t bytes) {
    if ((m->used + 1) * 2 > m->cap) ipmap_grow(m);
    size_t mask = m->cap - 1, i = hash32(ip) & mask;
    while (m->slots[i].flows && m->slots[i].ip != ip) i = (i + 1) & mask;
    if (!m->slots[i].flows) { m->slots[i].ip = ip; m->used++; }
    m->slots[i].flows += flows;
    m->slots[i].bytes += bytes;
}

void ipmap_merge(IpMap *dst, const IpMap *src) {
    for (size_t i = 0; i < src->cap; i++)
        if (src->slots[i].flows)
            ipmap_add(dst, src->slots[i].ip, src->slots[i].flows, src->slots[i].bytes);
}
